# /bin/bash

# Set of tests of API (not the function, just each call)

# Clearinghouse API test
python client.py --url https://localhost:8001/CH --method get_version --options_file /tmp/options.json
python client.py --url https://localhost:8001/CH --method get_slice_authorities --options_file /tmp/options.json
python client.py --url https://localhost:8001/CH --method get_member_authorities --options_file /tmp/options.json
python client.py --url https://localhost:8001/CH --method get_aggregates --options_file /tmp/options.json
python client.py --url https://localhost:8001/CH --method lookup_authorities_for_urns --options_file /tmp/urns.json


# MA API Test
python client.py --url https://localhost:8001/MA --method get_version --options_file /tmp/options.json
python client.py --url https://localhost:8001/MA --method lookup_public_member_info --options_file /tmp/options.json
python client.py --url https://localhost:8001/MA --method lookup_private_member_info --options_file /tmp/options.json
python client.py --url https://localhost:8001/MA --method lookup_identifying_member_info --options_file /tmp/options.json
python client.py --url https://localhost:8001/MA --method update_member_info --urn foo --options_file /tmp/options.json

# SA API Test
python client.py --url https://localhost:8001/SA --method get_version --options_file /tmp/options.json
python client.py --url https://localhost:8001/SA --method create_slice --options_file /tmp/options.json
python client.py --url https://localhost:8001/SA --method lookup_slices --options_file /tmp/options.json
python client.py --url https://localhost:8001/SA --method update_slice --urn foo --options_file /tmp/options.json
python client.py --url https://localhost:8001/SA --method get_credentials --urn foo --options_file /tmp/options.json
python client.py --url https://localhost:8001/SA --method modify_slice_membership --urn foo --options_file /tmp/options.json
python client.py --url https://localhost:8001/SA --method lookup_slice_members --urn foo --options_file /tmp/options.json
python client.py --url https://localhost:8001/SA --method register_aggregate --urn foo --agg_url bar --options_file /tmp/options.json
python client.py --url https://localhost:8001/SA --method remove_aggregate --urn foo --agg_url bar --options_file /tmp/options.json
python client.py --url https://localhost:8001/SA --method get_slice_aggregates --urn foo --options_file /tmp/options.json
python client.py --url https://localhost:8001/SA --method create_project --options_file /tmp/options.json
python client.py --url https://localhost:8001/SA --method lookup_projects --options_file /tmp/options.json
python client.py --url https://localhost:8001/SA --method update_project --urn foo --options_file /tmp/options.json
python client.py --url https://localhost:8001/SA --method modify_project_membership --urn foo --options_file /tmp/options.json
python client.py --url https://localhost:8001/SA --method lookup_project_members --urn foo --options_file /tmp/options.json


