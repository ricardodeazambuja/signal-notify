"""Shared-contact-card parsing (``DataMessage.Contact``).

Field numbers follow SignalService.proto: ``Contact.name`` is a nested
``Name`` message (field 1: givenName=1, familyName=2), there is **no field 2**,
and phone numbers are repeated nested ``Phone`` messages at field 3
(``Phone.value`` = 1). The pre-fix code read field 2 as a name and field 1 as
text, decoding raw protobuf bytes.
"""
from signalnotify.native.messaging import (encode_bytes_field, encode_content,
                                           encode_data_message,
                                           encode_string_field)
from signalnotify.native.receive import _parse_contacts, parse_content

CONTACT_FIELD = 9  # DataMessage.contact


def _name(given=None, family=None):
    body = b""
    if given:
        body += encode_string_field(1, given)
    if family:
        body += encode_string_field(2, family)
    return body


def _phone(value):
    return encode_string_field(1, value)


def _card(name=None, phones=(), bogus_field2=None):
    body = b""
    if name is not None:
        body += encode_bytes_field(1, name)
    if bogus_field2 is not None:
        body += encode_bytes_field(2, bogus_field2)
    for value in phones:
        body += encode_bytes_field(3, _phone(value))
    return body


def _dm_with_contacts(*cards):
    dm = encode_data_message("", 123)
    for card in cards:
        dm += encode_bytes_field(CONTACT_FIELD, card)
    return dm


def test_parse_contacts_name_and_number():
    dm = {CONTACT_FIELD: [_card(_name("Ada", "Lovelace"), ["+15551234567"])]}
    assert _parse_contacts(dm) == [{"name": "Ada Lovelace", "number": "+15551234567"}]


def test_parse_contacts_first_phone_only():
    dm = {CONTACT_FIELD: [_card(_name("Grace"), ["+1111", "+2222"])]}
    assert _parse_contacts(dm) == [{"name": "Grace", "number": "+1111"}]


def test_parse_contacts_ignores_reserved_field_2():
    # A card carrying only field 2 must NOT be read as a name (there is no
    # field 2 in Contact; the old code decoded its raw protobuf bytes as text).
    dm = {CONTACT_FIELD: [_card(bogus_field2=b"\x0a\x03abc")]}
    assert _parse_contacts(dm) == []


def test_parse_contacts_skips_unparseable_card():
    dm = {CONTACT_FIELD: [b"\xff\xff\xff", _card(_name("Ok"), ["+9"])]}
    assert _parse_contacts(dm) == [{"name": "Ok", "number": "+9"}]


def test_parse_content_populates_contacts():
    content = encode_content(data_message_bytes=_dm_with_contacts(
        _card(_name("Ada", "Lovelace"), ["+15551234567"])))
    msg = parse_content(content, self_ids={"+15550000000"}, source="+15559999999",
                        envelope_ts=123)
    assert msg is not None
    assert msg.contacts == [{"name": "Ada Lovelace", "number": "+15551234567"}]
