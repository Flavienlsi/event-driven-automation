import requests
from st2common.runners.base_action import Action

class UpdateFile(Action):

    def run(self, srcip, gitlab_url, branch_name, commit_message, private_token, repository_id, file_path):
        file_url = f"{gitlab_url}/api/v4/projects/{repository_id}/repository/files/{file_path}/raw?ref={branch_name}"
        headers = {'PRIVATE-TOKEN': private_token}
        response = requests.get(file_url, headers=headers)
        content = response.content.decode('utf-8')

        if srcip not in content:
            new_content = content + '\n' + srcip
            file_url = f"{gitlab_url}/api/v4/projects/{repository_id}/repository/files/{file_path}"
            headers = {
                'PRIVATE-TOKEN': private_token,
                'Content-Type': 'application/json'
            }
            data = {
                'branch': branch_name,
                'content': new_content,
                'commit_message': commit_message
            }
            requests.put(file_url, headers=headers, json=data)