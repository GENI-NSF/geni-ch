# Set of tests of PGCH API (not the function, just the XMLRPC call

python pgch_client.py --url https://localhost:8001/PGCH --method GetVersion 
python pgch_client.py --url https://localhost:8001/PGCH --method GetCredential --args_file /tmp/args.json
python pgch_client.py --url https://localhost:8001/PGCH --method Resolve --args_file /tmp/args.json
python pgch_client.py --url https://localhost:8001/PGCH --method Register --args_file /tmp/args.json
python pgch_client.py --url https://localhost:8001/PGCH --method RenewSlice  --args_file /tmp/args.json
python pgch_client.py --url https://localhost:8001/PGCH --method GetKeys  --args_file /tmp/args.json
python pgch_client.py --url https://localhost:8001/PGCH --method ListComponents --args_file /tmp/args.json


