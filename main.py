def define_env(env):
    @env.macro
    def spec_content(meta):
        topic = meta.get("topic", "No Topic")
        statement = meta.get("k8tre_statements", {}).get("spec", "No statement provided.")
        updated = meta.get("last_updated", "Unknown")
        source = meta.get("discussion") or "N/A"



        return f"""
# {topic}

!!! abstract "Specification"
    {statement}

Last updated: {updated}  
Source: {source}
"""
    
    
    @env.macro
    def satre_link(meta):
        satre_items = meta.get("k8tre_statements", {}).get("satre", [])

        # Build SATRE section only if items exist
        satre_md = ""
        if isinstance(satre_items, list) and satre_items:
            satre_md = "## SATRE components realised by this statement"
            for item in satre_items:
                ref = item.get("ref", "No ref")
                rationale = item.get("rationale", "No rationale provided.")
                satre_md += f"""
**Component {ref}**  
{rationale}
"""
                return satre_md