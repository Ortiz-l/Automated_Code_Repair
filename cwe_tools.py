from langchain.tools import tool
import requests

BASE_URL = "https://cwe-api.mitre.org/api/v1"

def get_ancestor_tree(cwe_id):
    url = f"{BASE_URL}/cwe/{cwe_id}/ancestors?view=1000"
    resp = requests.get(url)
    resp.raise_for_status()
    return resp.json()

def extract_pillar_ids(node, seen=None):
    if seen is None:
        seen = set()

    collected = []
    data = node.get("Data", {})
    cwe_id = data.get("ID")

    if data.get("Type") == "pillar_weakness" and cwe_id not in seen:
        collected.append(cwe_id)
        seen.add(cwe_id)

    parents = node.get("Parents") or []
    for parent in parents:
        collected.extend(extract_pillar_ids(parent, seen))

    return collected

def fetch_cwe_name(cwe_id):
    url = f"{BASE_URL}/cwe/weakness/{cwe_id}"
    try:
        resp = requests.get(url)
        resp.raise_for_status()
        data = resp.json()
        weaknesses = data.get("Weaknesses", [])
        if weaknesses:
            return weaknesses[0].get("Name", "<No name>")
        return "<No name>"
    except Exception:
        return "<No name>"

@tool
def get_cwe_context(cwe_id: str) -> str:
    """
    Given a CWE ID, this function returns a text summary of pillar ancestor 
    weaknesses (from View-1000) using MITRE's CWE API."""
    try:
        tree = get_ancestor_tree(cwe_id)
        if not tree:
            return f"No ancestor context found for CWE-{cwe_id}."

        pillar_ids = extract_pillar_ids(tree[0])
        if not pillar_ids:
            return f"No pillar weaknesses found for CWE-{cwe_id}."

        context_lines = [f"Pillar Weakness Ancestors of CWE-{cwe_id}:"]
        for pid in pillar_ids:
            name = fetch_cwe_name(pid)
            context_lines.append(f"- CWE-{pid}: {name}")

        return "\n".join(context_lines)

    except Exception as e:
        return f"Error retrieving ancestor context for CWE-{cwe_id}: {e}"
