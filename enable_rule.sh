#!/bin/bash
#ionsecadmin <<EOF
#1
#a key hmac_key256 key_1_32bytes.hmk
#q
#EOF

bpsecadmin <<EOF
1
#a {"event_set" : {"name" : "d_integrity", "desc":"default integrity event set"}}
#a {"event" : {"es_ref" : "d_integrity", "event_id" : "sop_corrupted_at_verifier", "actions" : [{"id" : "remove_sop"},{"id" : "remove_sop_target"} ] }}
#a {"event" : {"es_ref" : "d_integrity", "event_id" : "sop_missing_at_acceptor", "actions" : [{"id" : "remove_sop_target" }]}}
#a {"event" : {"es_ref" : "d_integrity", "event_id" : "sop_corrupted_at_acceptor", "actions" : [{"id" : "remove_sop_target" }] }}
#a {"policyrule" : {"desc" : "Integrity source rule", "filter" : {"rule_id" : 1, "role" : "s", "src" : "ipn:1.*", "dest" : "ipn:2.*", "tgt" : 1}, "spec" : {"svc" : "bib-integrity", "sc_id" : 1, "sc_parms" : [{"key_name" : "hmac_key256" }]}, "es_ref" : "d_integrity" }}
a {"event_set" : {"name" : "d_bcb_conf", "desc":"default bcb event set"}}
a {"event" : {"es_ref" : "d_bcb_conf", "event_id" : "sop_corrupted_at_acceptor", "actions" : [{"id" : "remove_sop_target"} ] }}
a {"event" : {"es_ref" : "d_bcb_conf", "event_id" : "sop_missing_at_acceptor", "actions" : [{"id" : "remove_sop_target" }]}}
a {"policyrule" : {"desc" : "Confidentiality source rule", "filter" : {"rule_id" : 198, "role" : "s", "src" : "ipn:1.2", "dest" : "ipn:2.2", "tgt" : 1}, "spec" : {"svc" : "bcb-confidentiality", "sc_id" : 2, "sc_parms" : [{"key_name" : "BPSecKey" }, {"aad_scope": "4"}, {"aes_variant":"3"}]}, "es_ref" : "d_bcb_conf" }}
a {"policyrule" : {"desc" : "Confidentiality source rule", "filter" : {"rule_id" : 199, "role" : "a", "src" : "ipn:2.2", "dest" : "ipn:1.2", "tgt" : 1}, "spec" : {"svc" : "bcb-confidentiality", "sc_id" : 2, "sc_parms" : [{"key_name" : "BPSecKey" }, {"aad_scope": "4"}, {"aes_variant":"3"}]}, "es_ref" : "d_bcb_conf" }}
a {"policyrule" : {"desc" : "Confidentiality source rule", "filter" : {"rule_id" : 200, "role" : "s", "src" : "ipn:1.2", "dest" : "ipn:3.2", "tgt" : 1}, "spec" : {"svc" : "bcb-confidentiality", "sc_id" : 2, "sc_parms" : [{"key_name" : "BPSecKey" }, {"aad_scope": "4"}, {"aes_variant":"3"}]}, "es_ref" : "d_bcb_conf" }}
a {"policyrule" : {"desc" : "Confidentiality source rule", "filter" : {"rule_id" : 201, "role" : "a", "src" : "ipn:3.2", "dest" : "ipn:1.2", "tgt" : 1}, "spec" : {"svc" : "bcb-confidentiality", "sc_id" : 2, "sc_parms" : [{"key_name" : "BPSecKey" }, {"aad_scope": "4"}, {"aes_variant":"3"}]}, "es_ref" : "d_bcb_conf" }}
a {"policyrule" : {"desc" : "Confidentiality source rule", "filter" : {"rule_id" : 202, "role" : "s", "src" : "ipn:1.2", "dest" : "ipn:4.2", "tgt" : 1}, "spec" : {"svc" : "bcb-confidentiality", "sc_id" : 2, "sc_parms" : [{"key_name" : "BPSecKey" }, {"aad_scope": "4"}, {"aes_variant":"3"}]}, "es_ref" : "d_bcb_conf" }}
a {"policyrule" : {"desc" : "Confidentiality source rule", "filter" : {"rule_id" : 203, "role" : "a", "src" : "ipn:4.2", "dest" : "ipn:1.2", "tgt" : 1}, "spec" : {"svc" : "bcb-confidentiality", "sc_id" : 2, "sc_parms" : [{"key_name" : "BPSecKey" }, {"aad_scope": "4"}, {"aes_variant":"3"}]}, "es_ref" : "d_bcb_conf" }}
q
EOF