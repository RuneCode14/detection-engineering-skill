# Detection Engineering Skill

An **LLM Agent Skill** that orchestrates VirusTotal, yarGen, and YARA rule expertise into a unified detection engineering pipeline.

## 🎯 What This Skill Does

```
Hash → VirusTotal → Download Sample → yarGen → Generate Rule → YARA Expert → Improve Rule → Deliver
```

This skill combines three existing skills into one seamless workflow:

1. **VirusTotal API** - Download samples by hash, get threat context
2. **yarGen** - Generate YARA rules from malware samples
3. **YARA Rule Expert** - Post-process and optimize generated rules

## 🚀 Quick Start

### One Command: Hash to YARA Rule

```bash
# Full pipeline
detection-engineer.sh generate-from-hash d41d8cd98f00b204e9800998ecf8427e \
  --author "Florian Roth" \
  --output MAL_Backdoor_Feb25.yar
```

### Step by Step

```bash
# 1. Download from VirusTotal
detection-engineer.sh download d41d8cd98f00b204e9800998ecf8427e \
  --save-sample /tmp/malware.bin

# 2. Generate YARA rule
detection-engineer.sh generate /tmp/malware.bin \
  --author "Security Team" \
  --output draft.yar

# 3. Review with YARA expert
detection-engineer.sh review draft.yar
```

## 📦 Installation

### Prerequisites

All three component skills must be installed:

```bash
# 1. VirusTotal API skill
ls ~/.openclaw/skills/virustotal-api/SKILL.md

# 2. yarGen skill  
ls ~/.openclaw/skills/yargen/SKILL.md

# 3. YARA Rule skill (packaged or directory)
ls ~/.openclaw/skills/yara-skill.skill
# OR
ls ~/.openclaw/skills/yara-rule-skill/SKILL.md
```

### Install This Skill

```bash
# Clone to skills folder
git clone https://github.com/YOURORG/detection-engineering-skill.git \
  ~/.openclaw/skills/detection-engineering

# Or copy from local workspace
cp -r ~/clawd/skills/detection-engineering ~/.openclaw/skills/
```

### Configure VirusTotal

```bash
# Set API key
echo "your-vt-api-key" > ~/.virustotal/apikey
```

## 🔧 Usage

### Full Pipeline Commands

```bash
# Basic usage
detection-engineer.sh generate-from-hash <hash>

# With all options
detection-engineer.sh generate-from-hash d41d8cd98f00b204e9800998ecf8427e \
  --author "Your Name" \
  --reference "https://threat-report.example.com" \
  --output rule.yar \
  --save-sample /samples/malware.bin \
  --verbose
```

### Options

| Option | Description |
|--------|-------------|
| `-a, --author <name>` | Rule author name |
| `-o, --output <file>` | Save rule to file (default: stdout) |
| `-r, --reference <ref>` | Reference URL or report ID |
| `--no-vt-context` | Skip VirusTotal metadata enrichment |
| `--skip-post-process` | Skip YARA expert review |
| `--save-sample <path>` | Keep downloaded sample |
| `-v, --verbose` | Show detailed progress |

### Batch Processing

```bash
# Process multiple hashes
for hash in $(cat hashes.txt); do
    detection-engineer.sh generate-from-hash $hash \
        --author "SOC Team" \
        --output "rules/${hash:0:16}.yar"
done
```

## 📊 Output

The final YARA rule includes enrichment from all three stages:

```yara
rule MAL_APT_CampaignX_Backdoor_Feb25 {
    meta:
        description = "Detection for Campaign X backdoor"
        author = "Security Team"
        date = "2025-02-07"
        hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        reference = "https://threat-report.example.com/campaign-x"
        vt_detection = "45/72"
        vt_tags = "backdoor,apt,trojan"
    strings:
        $x1 = "unique_campaign_string" fullword ascii
        $s1 = "suspicious_api_call" fullword ascii
    condition:
        uint16(0) == 0x5a4d and
        filesize < 500KB and
        (1 of ($x*) or 2 of ($s*))
}
```

## 🏗️ Architecture

```
┌─────────────────┐
│  User provides  │
│  hash           │
└────────┬────────┘
         ▼
┌─────────────────┐     ┌─────────────────┐
│  VirusTotal API │────▶│  Download       │
│  (vt-file-*)    │     │  sample         │
└─────────────────┘     └────────┬────────┘
                                 ▼
                        ┌─────────────────┐
                        │  yarGen Skill   │
                        │  (yargen-util   │
                        │   submit)       │
                        └────────┬────────┘
                                 ▼
                        ┌─────────────────┐
                        │  YARA Rule      │
                        │  Expert         │
                        │  (review/       │
                        │   optimize)     │
                        └────────┬────────┘
                                 ▼
                        ┌─────────────────┐
                        │  Final YARA     │
                        │  Rule           │
                        └─────────────────┘
```

## 🔒 Security Considerations

- **Sample Handling**: Downloaded samples are temporary by default
- **API Keys**: VT API key is read from secure location, never exposed
- **Retention**: Samples auto-deleted unless `--save-sample` specified
- **Rule Sharing**: Generated rules should be reviewed before distribution

## 🤝 Integration Examples

### MISP Integration
```bash
# Generate rules for all hashes in MISP event
misp_event_id=12345
misp-dump-hashes $misp_event_id | \
    xargs -I {} detection-engineer.sh generate-from-hash {} \
        -o "misp-${misp_event_id}/{}.yar"
```

### SIEM Alert Response
```bash
# Auto-generate rules for IOCs in SIEM alert
alert_id=$1
siem-get-iocs $alert_id | \
    detection-engineer.sh generate-from-hash {} \
        --reference "SIEM Alert $alert_id"
```

## 📝 TODO / Future Enhancements

- [ ] Full YARA expert integration (currently placeholder)
- [ ] Support for URL-based rules (not just file hashes)
- [ ] Batch processing with parallelization
- [ ] Automatic rule testing against sample corpus
- [ ] Integration with threat intel platforms (MISP, OpenCTI)
- [ ] Configuration file support

## 📄 License

See component skills for their respective licenses:
- VirusTotal API - See VirusTotal terms
- yarGen - See yarGen-Go repository
- YARA Rule Skill - See YARAHQ/yara-rule-skill

## 🙏 Acknowledgments

This skill is a meta-skill combining the work of:
- **Florian Roth** (@cyb3rops) - yarGen and YARA expertise
- **YARA HQ** - YARA rule skill and community
- **VirusTotal** - Threat intelligence platform
