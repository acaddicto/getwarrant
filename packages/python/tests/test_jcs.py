from warrant_fastapi import jcs, action_hash


def test_jcs_matches_core_vectors():
    # Same inputs as packages/core/test: {"b":1,"a":[1,{"d":undefined,"c":"x"}]} -> {"a":[1,{"c":"x"}],"b":1}
    assert jcs({"b": 1, "a": [1, {"d": None, "c": "x"}]}) == '{"a":[1,{"c":"x"}],"b":1}'
    assert jcs({"flight": "SQ529", "amount": 47800, "ccy": "USD"}) == '{"amount":47800,"ccy":"USD","flight":"SQ529"}'
    assert jcs(True) == "true" and jcs(None) == "null" and jcs(1.0) == "1" and jcs("é") == '"é"'


def test_action_hash_is_sha256_hex():
    h = action_hash({"flight": "SQ529", "fare": 47800})
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)
