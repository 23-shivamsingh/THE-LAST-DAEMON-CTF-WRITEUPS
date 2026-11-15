#!/usr/bin/env python3
"""The First Lead CTF — solve all 25 offline OSINT layers.

Usage:
    python3 solve_first_lead.py The_First_Lead_Player_Pack.zip
    python3 solve_first_lead.py first_lead/

Only Python's standard library is used. No internet access is required.
"""

import csv
import io
import json
import re
import sys
import zipfile
from pathlib import Path


class Evidence:
    def __init__(self, path):
        self.path = Path(path)
        if self.path.is_file() and zipfile.is_zipfile(self.path):
            self.archive = zipfile.ZipFile(self.path)
        elif self.path.is_dir():
            self.archive = None
        else:
            raise FileNotFoundError(f"Provide the ZIP file or an extracted folder: {path}")

    def text(self, name):
        if self.archive:
            return self.archive.read(name).decode("utf-8-sig")
        return (self.path / name).read_text(encoding="utf-8-sig")

    def json(self, name):
        return json.loads(self.text(name))

    def csv(self, name):
        return list(csv.DictReader(io.StringIO(self.text(name))))


def exactly_one(records, test, description):
    matches = [item for item in records if test(item)]
    if len(matches) != 1:
        raise ValueError(f"Expected 1 match for {description}; got {len(matches)}")
    return matches[0]


def note(layer, field, value):
    print(f"Layer {layer:02d} | {field:<22} | {value}")
    return value


def solve(e):
    # BAND 1: initial profile -> hobby -> employer -> group -> username
    html = e.text("evidence/platforms/circle/profiles/dev-kapoor.html")
    hobby_match = re.search(r"Weekends are for ([^;]+);", html)
    if hobby_match is None:
        raise ValueError("Layer 1: cannot extract hobby from profile bio")
    hobby = note(1, "hobby", hobby_match.group(1).strip())

    card = exactly_one(e.json("evidence/community/member_cards.json"),
                       lambda x: x["display_name"] == "Dev Kapoor" and hobby in x["interests"],
                       "member card for Dev Kapoor with exact hobby")
    workplace = note(2, "former_workplace", card["former_workplace"])

    worker = exactly_one(e.json("evidence/archives/workplace_directory.json"),
                         lambda x: x["name"] == "Dev Kapoor" and x["workplace"] == workplace,
                         "workplace directory")
    group = note(3, "community_group", worker["community_group"])

    member = exactly_one(e.csv("evidence/community/group_roster.csv"),
                         lambda x: x["group_name"] == group and x["member_name"] == "Dev Kapoor",
                         "volunteer roster")
    alias = note(4, "profile_alias", member["profile_alias"])

    settings = e.json("evidence/platforms/circle/account_settings/dk-447.json")
    assert settings["profile_alias"] == alias, "Layer 5 alias mismatch"
    username = note(5, "username", settings["username"])

    # BAND 2: username mini-index -> TownSquare -> TrailMap -> Pinboard
    index = e.json("evidence/indexes/username_mini_index.json")
    town_ref = exactly_one(index,
                           lambda x: x["username"] == username and x["platform"] == "TownSquare" and x["kind"] == "profile",
                           "TownSquare index")
    town_id = note(6, "TownSquare record_id", town_ref["record_id"])

    town = e.json(f"evidence/platforms/townsquare/users/{town_id}.json")
    assert town["username"] == username and town["display_name"] == "Dev Kapoor"
    trail_link = exactly_one(town["linked_accounts"],
                             lambda x: x["platform"] == "TrailMap", "TrailMap linked account")
    trail_handle = note(7, "trailmap_handle", trail_link["handle"])

    trail_ref = exactly_one(index,
                            lambda x: x["username"] == trail_handle and x["platform"] == "TrailMap",
                            "TrailMap index")
    trail_id = note(8, "TrailMap record_id", trail_ref["record_id"])

    trail = e.json(f"evidence/platforms/trailmap/users/{trail_id}.json")
    assert trail["username"] == trail_handle and trail["display_name"] == "Dev Kapoor"
    pin_link = exactly_one(trail["linked_accounts"],
                           lambda x: x["platform"] == "Pinboard", "Pinboard linked account")
    pin_handle = note(9, "pinboard_handle", pin_link["handle"])

    pin_ref = exactly_one(index,
                          lambda x: x["username"] == pin_handle and x["platform"] == "Pinboard" and x["kind"] == "profile",
                          "Pinboard index")
    pin = e.json(f"evidence/platforms/pinboard/users/{pin_ref['record_id']}.json")
    assert pin["username"] == pin_handle
    post_id = note(10, "photo_post_id", pin["photo_post_id"])

    # BAND 3: photo -> event -> venue -> landmark -> organizer -> joint event
    photo = exactly_one(e.json("evidence/archives/photo_posts.json"),
                        lambda x: x["post_id"] == post_id and x["author_handle"] == pin_handle,
                        "photograph caption")
    event_match = re.search(r"for the (.*?) with", photo["caption"])
    if event_match is None:
        raise ValueError("Layer 11: missing event name in photo caption")
    photo_event = note(11, "event_name", event_match.group(1))

    event_record = exactly_one(e.json("evidence/events/local_events.json"),
                               lambda x: x["event_name"] == photo_event,
                               "event archive")
    venue = note(12, "venue", event_record["venue"])

    location = exactly_one(e.json("evidence/archives/location_captions.json"),
                           lambda x: x["venue"] == venue and "landmark" in x and x["landmark"] in x["caption"],
                           "venue caption with named landmark")
    landmark = note(13, "landmark", location["landmark"])

    album = exactly_one(e.json("evidence/archives/album_captions.json"),
                        lambda x: landmark in x["caption"], "album mentioning the landmark")
    organizer = note(14, "organizer_handle", album["organizer_handle"])
    assert f"@{organizer}" in album["caption"], "Organizer must occur in caption"

    volunteer_caption = exactly_one(e.json("evidence/archives/volunteer_captions.json"),
                                    lambda x: x["author_handle"] == organizer and "Dev" in x["caption"] and "together" in x["caption"],
                                    "shared volunteer event")
    shared_event = note(15, "shared_event", volunteer_caption["event"])

    # BAND 4: social-graph contact and reciprocal follow verification
    conn = exactly_one(e.csv("evidence/social_graph/dev_kapoor_connections.csv"),
                       lambda x: shared_event in x["event_mentions"] and x["connection_type"] == "mutual",
                       "active mutual connection mentioning shared event")
    mutual_name = note(16, "mutual_contact_name", conn["contact_name"])

    detail = exactly_one(e.json("evidence/social_graph/connection_details.json"),
                         lambda x: x["display_name"] == mutual_name and x["relationship_type"] == "mutual" and x["handle"] == conn["contact_handle"],
                         "contact detail")
    contact_id = note(17, "contact_id", detail["contact_id"])

    second = exactly_one(e.json("evidence/social_graph/second_degree_connections.json"),
                         lambda x: x["contact_id"] == contact_id and any(y["account"] == username and y["direction"] == "both" for y in x["edges"]),
                         "second degree account connection")
    mutual_handle = note(18, "mutual_handle", second["handle"])

    relation = exactly_one(e.json("evidence/social_graph/profile_connections.json"),
                           lambda x: x["handle"] == mutual_handle and x["account"] == username and x["two_way_follow"] is True,
                           "reciprocal profile relationship")
    marker = note(19, "relationship_marker", relation["relationship_marker"])

    volunteer = exactly_one(e.csv("evidence/social_graph/event_volunteers.csv"),
                            lambda x: x["event"] == shared_event and x["volunteer_handle"] == mutual_handle and x["relationship_marker"] == marker and x["confirmation_status"] == "verified",
                            "verified event-volunteer entry")
    contact_key = note(20, "mutual_contact_key", volunteer["contact_key"])

    # BAND 5: three-signal candidate correlation -> current profile -> flag
    candidate = exactly_one(e.csv("evidence/finale/candidate_crossref.csv"),
                            lambda x: x["hobby"] == hobby and x["second_platform_handle"] == trail_handle and x["mutual_contact_key"] == contact_key,
                            "three independent identity signals")
    assert candidate["account_status"] == "current" and candidate["record_state"] == "verified"
    account_id = note(21, "account_id", candidate["account_id"])

    registry = exactly_one(e.json("evidence/finale/account_registry.json"),
                           lambda x: x["account_id"] == account_id and x["account_status"] == "current",
                           "current account registry")
    recovery_code = note(22, "recovery_code", registry["recovery_code"])

    recovery = exactly_one(e.json("evidence/finale/recovery_messages.json"),
                           lambda x: x["recovery_code"] == recovery_code and "current Dev Kapoor" in x["message"],
                           "current account recovery message")
    account_label = note(23, "account_label", recovery["account_label"])

    route = exactly_one(e.json("evidence/finale/profile_route_index.json"),
                        lambda x: x["account_label"] == account_label and x["profile_path"] == registry["profile_path"],
                        "resolved current profile route")
    note(24, "profile_path", route["profile_path"])
    note(24, "route_token", route["route_token"])

    profile = e.json(route["profile_path"])
    assert profile["account_id"] == account_id, "Final account ID mismatch"
    assert profile["account_status"] == "current", "Final profile not current"
    assert profile["route_token"] == route["route_token"], "Invalid route token"
    match = re.search(r"flag\{[^}\s]+\}", profile["bio"])
    if match is None:
        raise ValueError("Layer 25: flag not found in verified bio")
    flag = note(25, "FLAG", match.group(0))
    print("\n[+] All 25 layers validated successfully!")
    print(f"[+] FINAL FLAG: {flag}")
    return flag


if __name__ == "__main__":
    source = sys.argv[1] if len(sys.argv) > 1 else "The_First_Lead_Player_Pack.zip"
    try:
        solve(Evidence(source))
    except (OSError, KeyError, AssertionError, ValueError, zipfile.BadZipFile) as error:
        print(f"[!] Solve failed: {error}", file=sys.stderr)
        sys.exit(1)
