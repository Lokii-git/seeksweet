# NessusSeek - vRPA Quick Deploy Guide

## Problem Solved
**Issue:** Disposable vRPAs require manual Nessus activation for every engagement  
**Solution:** Automated activation + API key management = Deploy once, scan forever!

---

## 🚀 Fresh vRPA Setup (3 Minutes)

### FASTEST: Import from Backup (Recommended for Repeat Deployments!) ⚡

**Export once, reuse forever across all your disposable vRPAs!**

#### First Time Setup (On Any Existing Nessus):
```bash
# Export your configured Nessus (license, settings, plugins)
cd /opt/seeksweet/nessusseek
./export_nessus.sh

# Output: nessus_backup_YYYYMMDD_HHMMSS.tar
# Save this file - you'll use it for ALL future vRPAs!
```

#### Every New vRPA After That:
```bash
# 1. Transfer backup
scp nessus_backup_*.tar user@new-vrpa:/tmp/

# 2. Import (instant activation!)
cd /opt/seeksweet/nessusseek
./activate_nessus.sh --import /tmp/nessus_backup_*.tar

# 3. Run scans immediately!
source ~/.nessus_keys
./nessusseek.py -t iplist.txt
```

**Why this is amazing:**
- ⚡ **Instant activation** - No waiting for plugin downloads!
- 🔑 **One license** - Move it between vRPAs freely (disposable use case)
- 💾 **All settings preserved** - Users, policies, everything
- 🚀 **3-minute deployment** - Export once, import everywhere

---

### ALTERNATIVE: Fresh Activation (First Time or No Backup)

#### Step 1: Pull SeekSweet
```bash
cd /opt
git clone https://github.com/Lokii-git/seeksweet.git
cd seeksweet/Internal/seeksweet/nessusseek
chmod +x activate_nessus.sh export_nessus.sh nessusseek.py
```

#### Step 2: Run Activation Script
```bash
# One command to rule them all
./activate_nessus.sh XXXX-XXXX-XXXX-XXXX

# Or let it prompt you for the code
./activate_nessus.sh
```

**What it does:**
- ✅ Starts Nessus service
- ✅ Waits for initialization (60-90s)
- ✅ Activates with your Essentials code
- ✅ Creates admin user (admin/changeme123!)
- ✅ Generates API keys automatically
- ✅ Saves to `~/.nessus_keys`

#### Step 3: Export for Future vRPAs
```bash
# After plugins download (30-60 min), export once:
./export_nessus.sh

# Save this backup - use it for all future vRPAs!
```

#### Step 4: Run Scans
```bash
# Load credentials once per session
source ~/.nessus_keys

# Run scans all engagement long!
./nessusseek.py -t ../iplist.txt -n "Client-External-Scan"
./nessusseek.py -t internal_ips.txt -n "Client-Internal-Scan"
```

---

## 📋 Engagement Workflow

### Recommended: Import/Export Pattern (One License, Many vRPAs)

**Initial Setup (Once):**
```bash
# Set up Nessus on your first vRPA
./activate_nessus.sh YOUR-NESSUS-CODE
# Wait for plugins to download (30-60 min)
./export_nessus.sh
# Save nessus_backup_*.tar to your secure storage
```

**Every New Engagement:**
```bash
# Deploy fresh vRPA
git clone https://github.com/Lokii-git/seeksweet.git /opt/seeksweet
cd /opt/seeksweet/Internal/seeksweet/nessusseek

# Import previous config (instant activation!)
./activate_nessus.sh --import ~/nessus_backup_*.tar

# Scan immediately!
source ~/.nessus_keys
./nessusseek.py -t scope.txt -n "Initial-Scan"
```

**During Engagement:**
```bash
# Each terminal session
source ~/.nessus_keys

# Run scans as needed
./nessusseek.py -t scope.txt -n "Initial-Scan"
./nessusseek.py -t new_targets.txt -n "Expanded-Scan"
./nessusseek.py --list  # Check scan status
```

**Engagement Complete:**
```bash
# Destroy vRPA
# No re-activation needed - your backup works for next client!
# One license = unlimited disposable vRPAs (one at a time)
```

---

### Alternative: Fresh Activation Per Engagement

### Day 0 - Deployment
```bash
# On fresh Kali/vRPA
git clone https://github.com/Lokii-git/seeksweet.git /opt/seeksweet
cd /opt/seeksweet/Internal/seeksweet/nessusseek
./activate_nessus.sh YOUR-NESSUS-CODE
```

### Day 1-X - Scanning
```bash
# Each terminal session
source ~/.nessus_keys

# Run scans as needed
./nessusseek.py -t scope.txt -n "Initial-Scan"
./nessusseek.py -t new_targets.txt -n "Expanded-Scan"
./nessusseek.py --list  # Check scan status
```

### Engagement Complete
```bash
# Destroy vRPA
# All credentials are local to the box
# Next engagement = fresh start!
```

---

## 🔑 Getting Your Nessus Essentials Key

**FREE for personal/professional use (16 IPs)**

1. Visit: https://www.tenable.com/products/nessus/nessus-essentials
2. Fill out form (work email works fine)
3. Receive activation code via email: `XXXX-XXXX-XXXX-XXXX`
4. Keep this code safe - you'll use it for every vRPA deployment

**Pro Tip:** Save your activation code in your password manager or secure notes!

---

## 🛠️ Advanced Usage

### Environment Variables (Alternative to activate_nessus.sh)
```bash
# Manually set credentials
export NESSUS_ACCESS_KEY="abc123..."
export NESSUS_SECRET_KEY="xyz789..."
export NESSUS_URL="https://localhost:8834"

# Run without sourcing file
./nessusseek.py -t targets.txt
```

### Python API Activation (Alternative Method)
```bash
# If you already have API keys from Web UI
./nessusseek.py --activation-code XXXX-XXXX-XXXX \
  --access-key YOUR_KEY \
  --secret-key YOUR_SECRET
```

### Remote Nessus Instance
```bash
# Scan from different box
export NESSUS_URL="https://192.168.1.100:8834"
./nessusseek.py -t targets.txt
```

---

## 📊 Output Files

All results saved to current directory:

| File | Contents |
|------|----------|
| `nessuslist.txt` | Vulnerable hosts with severity counts |
| `nessus_findings.txt` | Detailed Critical/High findings |
| `nessus_results.csv` | Full Nessus CSV export |
| `NESSUS_GUIDE.txt` | Remediation guidance |

---

## ⚡ Troubleshooting

### "Connection refused"
```bash
# Start Nessus service
sudo systemctl start nessusd
sudo systemctl status nessusd

# Wait 60-90 seconds for initialization
```

### "Authentication failed"
```bash
# Reset admin password via Web UI
# Then regenerate API keys: Settings → API Keys
# Update ~/.nessus_keys with new keys
```

### "No scans available" / Template errors
```bash
# Wait for plugin download (first-time only)
# Can take 30-60 minutes
# Check status: https://localhost:8834
```

### Manual API Key Generation
```bash
# If activate_nessus.sh fails
# 1. Browse to: https://localhost:8834
# 2. Login: admin / changeme123!
# 3. Settings → API Keys → Generate
# 4. Copy to ~/.nessus_keys manually
```

---

## 🎯 Why This Rocks

**Before:**
1. Deploy vRPA
2. SSH in, start Nessus
3. Browse to Web UI
4. Manual activation (paste code)
5. Wait for setup
6. Create user
7. Generate API keys
8. Copy/paste keys
9. Finally run scan
10. **Repeat for EVERY engagement** 😫

**After:**
1. Deploy vRPA
2. `./activate_nessus.sh YOUR-CODE`
3. `source ~/.nessus_keys`
4. `./nessusseek.py -t targets.txt`
5. ☕ Coffee time! ✨

---

## 💡 Team Best Practices

### Save Your Activation Code
```bash
# Add to team password manager
# Label: "Nessus Essentials Activation"
# Code: XXXX-XXXX-XXXX-XXXX
```

### Pre-Built vRPA Template (Optional)
```bash
# After first activation on a vRPA:
# 1. Complete activation
# 2. Let plugins download fully
# 3. Snapshot the VM
# 4. Use snapshot for future engagements
# Note: API keys rotate per deployment, but activation stays!
```

### Credential Management
```bash
# ~/.nessus_keys is local to each vRPA
# No secrets in git
# No credential reuse between clients
# Fresh keys per engagement = perfect isolation
```

---

## 📞 Support

**Issues?**
- GitHub: https://github.com/Lokii-git/seeksweet/issues
- Check: `nessusseek/README.md` for full documentation

**Nessus Essentials Support:**
- Community: https://community.tenable.com/
- Docs: https://docs.tenable.com/nessus/

---

**Happy Hunting! 🎯**
