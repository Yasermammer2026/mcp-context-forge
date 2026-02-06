import subprocess
import json

# basic function to clone the target repository into a new folder temp_repo; 
# only copies most recent version of repository; can be better optimised
def clone_repo(repo_url: str, temp_folder: str):
    subprocess.run(["git", "clone", "--depth", "1",
                    repo_url, temp_folder],
                   check=True)

# deletes the temporary folder
def delete_temp_repo(temp_folder: str):
    subprocess.run(["rm", "-rf", temp_folder],
                   check=True)

# Run Semgrep scan on the files in the target repository, 
# using generic security rulesets and language-specific ones, then output JSON results
# Current method: brute force; scan for every language by default
def semgrep_scan(temp_folder: str):
    commands = ["semgrep", "scan", 
                "--config", "p/security-audit",
                "--config", "p/secrets",
                "--config", "p/owasp-top-ten",
                "--config", "p/python", 
                "--config", "p/javascript", 
                "--config", "p/java", 
                "--config", "p/golang", 
                "--json", "--json-output=semgrep.json", temp_folder]
    
    # produce SARIF output
    """ commands = ["semgrep", "scan", 
                "--config", "p/security-audit",
                "--config", "p/secrets",
                "--config", "p/owasp-top-ten",
                "--config", "p/python", 
                "--config", "p/javascript", 
                "--config", "p/java", 
                "--config", "p/golang", 
                "--sarif", "--sarif-output=semgrep.sarif", temp_folder] """
    try:
        result = subprocess.run(
        commands,
        capture_output=True,
        text=True,
    )
        data = json.loads(result.stdout)
        return data
    except Exception as e:
        print("error")
        return {"error": f"Failed to run Semgrep: {str(e)}"}

# cloning of repository into temporary folder, scanning then deleting temporary folder, in one function    
def clone_and_semgrep_scan(git_url: str, temp_folder: str):
    clone_repo(git_url, temp_folder)
    semgrep_scan(temp_folder)
    delete_temp_repo(temp_folder)