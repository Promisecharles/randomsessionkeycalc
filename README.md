# randomsessionkeycalc.py
This code generates random session key using your session key.
for smb2/smb3 decryption of traffic. it uses session key, username, domain, NTproofstr and password.
it also uses hashes of the user, but you have to modify the code and change the --password -p aurgument to --hashes -H if you are using the hash as password in cases where the hashes can not be decrypted.

Usage for rkgenwithpass.py

python3 script.py -u user -d domain -p password -n ntproofstr -k key

usage for rkgenwithhash.py

python3 keycalc-script-hash.py -u user -H hash -d domain -n NTProofStr -k key -v
