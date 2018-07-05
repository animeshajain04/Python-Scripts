import requests, json, sys


def get_key_vault(dictionary_list):
    for dic in dictionary_list:
        if dic["type"] == "Microsoft.KeyVault/vaults":
            return dic

def get_data_factory(dictionary_list):
    for dic in dictionary_list:
        if dic["type"] == "Microsoft.DataFactory/factories":
            return dic


print("Step-0 : Get IMS Token")
#url = "https://ims-na1-stg1.adobelogin.com/ims/token"
url = "https://ims-na1.adobelogin.com/ims/token"
payload = "grant_type=authorization_code&client_id=acp_foundation_connectors&client_secret=0b9edb1b-9a1a-4a31-8a44-965a904d71d4&code=-*******"
headers = {
    'Content-Type': "application/x-www-form-urlencoded"
    }

response = requests.request("POST", url, data=payload, headers=headers)
dict_object = json.loads(response.text)
if "error" in dict_object:
    print("\t\t\t\t[FAILED]\n\n")
    sys.exit(1)

print("\t\t\t\t[PASSED] Token : {0}\n\n".format( dict_object["access_token"] ))
token = dict_object["access_token"]

imsorgids = [
    "265D50A15A7B8B540A495D61",
    "32FF36555AC782A80A495C98"
]

imsorgid = [
    "4F3BB22C5631222A7F000101"
]



for org in imsorgids:
    print("Step-1 : Get Resources for Org [{0}]".format(org))

#    url = "https://platform-stage.adobe.io/data/infrastructure/discovery/customer/resources"
    url = "https://platform.adobe.io/data/infrastructure/discovery/customer/resources"
    headers = {
        'Authorization': "Bearer "+token,
        'Content-Type': "application/json",
        'x-api-key': "acp_foundation_connectors",
        'x-gw-ims-org-id': org+"@AdobeOrg"
    }
    response = requests.request("GET", url, headers=headers)
    response_dict = json.loads(response.text)
    data_factory = get_data_factory(response_dict)
    key_vault = get_key_vault(response_dict)
    #print("\t\t [DEBUG] Data Factory : {0}".format(data_factory))
    print("Step-2 : Patching ADF")
    if "identity" in data_factory:
        print("\t\tIdentity already exist in ADF, not patching ADF")
        adf_tenantid = data_factory["identity"]["tenantId"]
        adf_principalId = data_factory["identity"]["principalId"]
    else:
        #
        # Get token for ADF
        #
        url = "https://login.windows.net/fa7b1b5a-7b34-4387-94ae-d2c178decee1/oauth2/token"
        querystring = {"api-version": "2017-09-01-preview"}
        payload = "grant_type=client_credentials&resource=https%3A%2F%2Fmanagement.azure.com%2F&client_secret="+data_factory["clientKey"]+"&client_id="+data_factory["clientId"]
        headers = {
            'Content-Type': "application/x-www-form-urlencoded"
        }
        response = requests.request("POST", url, data=payload, headers=headers, params=querystring)
        #print("\t\t [DEBUG] MSFT Token : {0}".format(json.loads(response.text)["access_token"]))
        msft_token = json.loads(response.text)["access_token"]


        #
        # Patch ADF
        #
        url = "https://management.azure.com"+data_factory["id"]
        querystring = {"api-version": "2017-09-01-preview"}
        payload = "{\n    \"name\": \"" +data_factory["name"]+"\",\n    \"location\": \"eastUS2\",\n    \"properties\": {},\n    \"identity\": {\n        \"type\": \"SystemAssigned\"\n    }\n}"

        headers = {
            'Authorization': "Bearer "+msft_token,
            'x-ms-datafactory-appmodel': data_factory["name"],
            'Content-Type': "application/json"
        }

        response = requests.request("PATCH", url, data=payload, headers=headers, params=querystring)
        #print("\t\t [DEBUG] Response : {0}".format(response.text))
        if "identity" in json.loads(response.text):
            print("\t\t [DEBUG] Patching successful....")
            adf_tenantid = json.loads(response.text)["identity"]["tenantId"]
            adf_principalId = json.loads(response.text)["identity"]["principalId"]
        else:
            print("\t\t [ERROR] Patching Failed...")
            sys.exit(1)

    print("Step - 3 : Adding Policy in AKV")
    url = "https://login.windows.net/fa7b1b5a-7b34-4387-94ae-d2c178decee1/oauth2/token"
    querystring = {"api-version": "2017-09-01-preview"}
    # Code returned KV credentials : payload = "grant_type=client_credentials&resource=https%3A%2F%2Fmanagement.azure.com%2F&client_secret=" + key_vault["clientKey"] + "&client_id=" + key_vault["clientId"]
    # int : payload = "grant_type=client_credentials&resource=https%3A%2F%2Fmanagement.azure.com%2F&client_secret=Doqhdls8w5JA7zdIEKBlLq57cli4NFUz%2F%2BZsHtxERV4%3D&client_id=9d5ceea7-f510-4646-9406-7abc23ed1f0f"
    # stage : payload = "grant_type=client_credentials&resource=https%3A%2F%2Fmanagement.azure.com%2F&client_secret=8ec6bf60-f022-4b6c-91be-718d737966a2&client_id=0ad2979a-083c-49fb-8642-0dcb2238e104"
    payload = "grant_type=client_credentials&resource=https%3A%2F%2Fmanagement.azure.com%2F&client_secret=vaGcYQgsDDDzrrQr************&client_id=3f50c8db-********-b1e6-f0789f8e4155"
    #print(payload)
    headers = {
        'Content-Type': "application/x-www-form-urlencoded"
    }
    response = requests.request("POST", url, data=payload, headers=headers, params=querystring)
    #print("\t\t [DEBUG] MSFT Token : {0}".format(json.loads(response.text)["access_token"]))
    msft_token = json.loads(response.text)["access_token"]

    #
    # Creating Policy in Vault
    #
    url = "https://management.azure.com"+key_vault["id"] +"/accessPolicies/add"
    querystring = {"api-version": "2018-02-14-preview"}
    #payload = "{\n  \"properties\": {\n   \"accessPolicies\": [\n      {\n        \"objectId\": \"6bf5e241-4c74-45bf-a7a3-3f79438a742a\",\n        \"tenantId\": \"fa7b1b5a-7b34-4387-94ae-d2c178decee1\",\n        \"permissions\": {\n          \"keys\": [\"encrypt\"],\n          \"secrets\": [\"get\"],\n          \"certificates\": [\"get\"]\n        }\n      }\n    ]\n  }\n}"
    payload = "{\n  \"properties\": {\n   \"accessPolicies\": [\n      {\n        \"objectId\": \"" +adf_principalId+"\",\n        \"tenantId\": \""+adf_tenantid+"\",\n        \"permissions\": {\n          \"keys\": [\"encrypt\"],\n          \"secrets\": [\"get\"],\n          \"certificates\": [\"get\"]\n        }\n      }\n    ]\n  }\n}"
    headers = {
        'Authorization': "Bearer "+msft_token,
        'Content-Type': "application/json"
    }
    response = requests.request("PUT", url, data=payload, headers=headers, params=querystring)
    print(response.text)
    #print("\t\t [DEBUG] AKV Policy Response : {0}".format(response.text))
    if "objectId" in json.loads(response.text)["properties"]["accessPolicies"][0]:
        print("\t\t [DEBUG] Policy Added Successfully...")
    else:
        print("\t\t [DEBUG] Policy Addition Failed...")


#    print("\tADF : {0}".format(data_factory))
#    print("\tAKV : {0}".format(key_vault))
#    print(json.loads(response.text))


