from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import jwt
import requests
import binascii
import os

KEY = os.getenv('AES_KEY', 'Yg&tc%DEuh6%Zc^8')[:16]
IV = os.getenv('AES_IV', '6oyZDr22E3ychjM%')[:16]

def encrypt_data(data):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded = pad(data, AES.block_size)
    return cipher.encrypt(padded)

def handler(request):
    try:
        # Get query parameters
        jwt_token = request.args.get('jwt')
        bio_text = request.args.get('bio_text')
        region = request.args.get('region', 'INF').upper()
        
        # Parse JWT payload
        payload = jwt.decode(jwt_token, options={"verify_signature": False})
        account_id = payload.get('account_id')
        
        # Create protobuf-like payload
        proto_data = {
            '1': account_id,  # account_id field number
            '2': bio_text,    # bio_text field number
            '3': region       # region field number
        }
        proto_str = json.dumps(proto_data).encode()
        
        # Encrypt data
        encrypted_data = encrypt_data(proto_str)
        
        # Determine endpoint
        endpoints = {
            'IND': 'https://client.ind.freefiremobile.com/UpdateBio',
            'BR': 'https://client.us.freefiremobile.com/UpdateBio',
            'INF': 'https://client.ind.freefiremobile.com/UpdateBio',
            'NA': 'https://clientbp.ggblueshark.com/UpdateBio'
        }
        endpoint = endpoints.get(region, endpoints['INF'])
        
        # Send request to game server
        response = requests.post(
            endpoint,
            data=encrypted_data,
            headers={
                'Authorization': f'Bearer {jwt_token}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        )
        
        # Return formatted response
        return json.dumps({
            "message": "Bio updated successfully",
            "response": response.content.decode('latin-1'),
            "status": "success"
        }), 200, {'Content-Type': 'application/json'}
        
    except Exception as e:
        return json.dumps({
            "message": str(e),
            "response": "",
            "status": "error"
        }), 500, {'Content-Type': 'application/json'}
