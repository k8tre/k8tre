def define_env(env):
    @env.macro
    def spec_content(meta):
        topic = meta.get("topic", "No Topic")
        statement = meta.get("k8tre_statements", {}).get("spec", "No statement provided.")
        updated = meta.get("last_updated", "Unknown")
        source = meta.get("discussion", "N/A")

        # SATRE entries — this becomes a Python list of dicts
        satre_items = meta.get("k8tre_statements", {}).get("satre", [])

        # Build SATRE section (if any)
        satre_md = ""
        if isinstance(satre_items, list) and satre_items:
            satre_md += "## SATRE Mapping"
            for item in satre_items:
                ref = item.get("ref", "No ref")
                rationale = item.get("rationale", "No rationale provided.")
                satre_md += f"""
**Component {ref}**  
*{rationale}*\n
"""

        return f"""
# {topic}

!!! abstract "Specification"
    {statement}

Last updated: {updated}  
Source: {source if source else "N/A"}

{satre_md}
"""
