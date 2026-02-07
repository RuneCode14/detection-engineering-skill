---
name: detection-engineering
description: End-to-end malware detection engineering workflow. Download samples from VirusTotal by hash, generate YARA rules using yarGen, and post-process with expert review using yara-rule-skill. Use when creating high-quality YARA rules from malware hashes, improving detection coverage, or building detection content from threat intelligence.
---

# Detection Engineering Skill

A unified workflow that combines VirusTotal, yarGen, and YARA rule expertise into a single detection engineering pipeline.

## The Workflow

```
Hash → VirusTotal → Download Sample → yarGen → Generate Rule → YARA Expert → Improve Rule → Deliver
```

### Step 1: VirusTotal (Sample Acquisition)
Use the `virustotal-api` skill to:
- Look up file hash metadata
- Download the sample (if available and permitted)
- Get file context (detections, tags, behavioral data)

### Step 2: yarGen (Rule Generation)
Use the `yargen` skill to:
- Extract strings from the sample
- Filter against goodware databases
- Generate initial YARA rule

### Step 3: YARA Rule Expert (Post-Processing)
Use the `yara-rule-skill` to:
- Review the generated rule for quality issues
- Optimize performance (condition ordering, atom selection)
- Apply naming conventions
- Validate against yaraQA checks

## Quick Start

```bash
# Full workflow: hash → YARA rule
detection-engineer.sh generate-from-hash <hash> [options]

# Example
detection-engineer.sh generate-from-hash d41d8cd98f00b204e9800998ecf8427e \
  --author "Florian Roth" \
  --output rule.yar
```

## Prerequisites

All three component skills must be installed:

```bash
# 1. VirusTotal API skill
ls ~/.openclaw/skills/virustotal-api/SKILL.md

# 2. yarGen skill  
ls ~/.openclaw/skills/yargen/SKILL.md

# 3. YARA Rule skill
ls ~/.openclaw/skills/yara-skill.skill
# or
ls ~/.openclaw/skills/yara-rule-skill/SKILL.md
```

And their dependencies:
- VirusTotal API key configured
- yarGen-Go built and databases downloaded
- yaraQA installed (optional, for validation)

## Usage

### Full Pipeline (Hash to Rule)

```bash
$SKILL_DIR/scripts/detection-engineer.sh generate-from-hash <hash> [options]

Options:
  -a, --author <name>      Rule author (default: yarGen)
  -o, --output <file>      Output file (default: stdout)
  --reference <ref>        Reference URL/report
  --no-vt-context          Skip VT metadata enrichment
  --skip-post-process      Skip YARA expert review
  --save-sample <path>     Keep downloaded sample
  --verbose                Show detailed progress
```

### Output

**The final improved YARA rule is ALWAYS displayed**, even without `-o` flag:

```bash
# Shows rule + expert review on screen
detection-engineer.sh generate-from-hash <hash>

# Shows rule + saves to file
detection-engineer.sh generate-from-hash <hash> -o rule.yar

# Both original and improved rules saved:
#   - rule.yar (improved version)
#   - rule_original.yar (raw yarGen output)
```

**Output includes:**
1. VirusTotal lookup results
2. Download confirmation
3. yarGen rule generation
4. **YARA Expert Review** (issues found + suggestions)
5. **Final Improved Rule** (production-ready)

### Individual Steps

```bash
# Just download from VT
$SKILL_DIR/scripts/detection-engineer.sh download <hash> --output /tmp/sample.bin

# Just generate from existing sample
$SKILL_DIR/scripts/detection-engineer.sh generate <sample-path> -a "Author"

# Just review existing rule
$SKILL_DIR/scripts/detection-engineer.sh review <rule-file>

# Full manual pipeline
$SKILL_DIR/scripts/detection-engineer.sh download d41d8cd98f00b204e9800998ecf8427e --output /tmp/malware.bin
$SKILL_DIR/scripts/detection-engineer.sh generate /tmp/malware.bin -o /tmp/draft.yar
$SKILL_DIR/scripts/detection-engineer.sh review /tmp/draft.yar
```

## Example Workflow

### Scenario: Create Rule from VT Hash

```bash
# Input: SHA256 hash from threat intel
HASH="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Run full pipeline
detection-engineer.sh generate-from-hash $HASH \
  --author "Security Team" \
  --reference "https://threat-report.example.com/campaign-x" \
  --output MAL_CampaignX_Backdoor.yar \
  --verbose

# Output will include:
# - VT lookup results (detections, file type, tags)
# - Generated rule with metadata
# - Expert review suggestions
# - Final improved rule
```

### Scenario: Batch Processing

```bash
# File with hashes, one per line
cat hashes.txt | while read hash; do
    detection-engineer.sh generate-from-hash $hash \
        --author "SOC Team" \
        --output "rules/${hash:0:16}.yar"
done
```

## Rule Output Format

The final rule includes enrichment from all three stages:

```yara
rule MAL_APT_CampaignX_Backdoor_Feb25 {
    meta:
        description = "Detection for Campaign X backdoor"
        author = "Security Team"
        date = "2025-02-07"
        hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        reference = "https://threat-report.example.com/campaign-x"
        vt_detection = "45/72"
        vt_tags = "backdoor,apt, trojan"
        score = 85
        // yaraQA: validated
    strings:
        $x1 = "unique_campaign_string" fullword ascii
        $s1 = "suspicious_behavior_1" fullword ascii
        $s2 = "suspicious_behavior_2" fullword ascii
        $fp1 = "common_benign_string" fullword ascii
    condition:
        uint16(0) == 0x5a4d and
        filesize < 500KB and
        (1 of ($x*) or 2 of ($s*)) and
        not $fp1
}
```

## Post-Processing Improvements

The YARA rule expert stage applies:

### 1. Naming Convention
- Prefix: `MAL_`, `SUSP_`, `HKTL_`, `APT_`
- Structure: `MAL_ACTOR_TYPE_DATE`

### 2. String Optimization
- `$x*` — Highly specific (unique) strings
- `$s*` — Grouped strings (need multiple)
- `$a*` — Pre-selection (file type narrowing)
- `$fp*` — False positive filters

### 3. Condition Optimization
- Magic header first (`uint16(0) == 0x5a4d`)
- Filesize check second
- Expensive checks last

### 4. Quality Checks (yaraQA)
- Logic errors (impossible conditions)
- Performance issues (short atoms, unanchored regex)
- Style violations (naming, formatting)

## VT Context Enrichment

When `--no-vt-context` is not set, the rule includes:

| Field | Source | Purpose |
|-------|--------|---------|
| `hash` | VT file lookup | Sample identification |
| `vt_detection` | VT stats | Prevalence info |
| `vt_tags` | VT tags | Threat classification |
| `first_seen` | VT first submission | Timeline |
| `file_type` | VT file_type | Context |

## Error Handling

| Scenario | Action |
|----------|--------|
| Hash not in VT | Report "Sample not found" |
| VT download fails | Report "Download permission denied" |
| yarGen fails | Report generation error |
| YARA review finds critical issues | Report with suggestions |

## Configuration

Create `~/.detection-engineer/config.yaml`:

```yaml
virustotal:
  api_key_file: ~/.virustotal/apikey

yargen:
  server_url: http://127.0.0.1:8080
  dbs_dir: ~/clawd/projects/yarGen-Go/repo/dbs

defaults:
  author: "Detection Engineering Team"
  output_dir: ./rules
  save_samples: false
  sample_retention: 7d  # Auto-delete after 7 days
```

## Security Considerations

- **Sample Handling**: Downloaded samples are temporary by default
- **API Keys**: VT API key never exposed in output
- **Rule Sharing**: Generated rules reviewed before distribution
- **Retention**: Configure sample retention policy

## Integration with Workflows

### MISP Integration
```bash
# Pull hashes from MISP event, generate rules
misp_event_id=12345
misp-dump-hashes $misp_event_id | \
    xargs -I {} detection-engineer.sh generate-from-hash {} -o "misp-${misp_event_id}/{}.yar"
```

### SIEM Integration
```bash
# Generate rules for IOCs in SIEM alert
alert_id=$1
siem-get-iocs $alert_id | \
    detection-engineer.sh generate-from-hash {} --reference "SIEM Alert $alert_id"
```

## See Also

- **virustotal-api skill**: `~/.openclaw/skills/virustotal-api/`
- **yargen skill**: `~/.openclaw/skills/yargen/`
- **yara-rule-skill**: `~/.openclaw/skills/yara-rule-skill/`

## References

- [VirusTotal API Docs](https://developers.virustotal.com/)
- [yarGen-Go Repository](https://github.com/Neo23x0/yarGen-Go)
- [YARA Documentation](https://yara.readthedocs.io/)
- [YARA Performance Guidelines](https://github.com/Neo23x0/YARA-Performance-Guidelines)
