# Contributing to SeekSweet

Thank you for your interest in contributing to SeekSweet! We welcome contributions from the community.

## 🤝 How to Contribute

### Reporting Bugs

Before creating a bug report, please:
1. Check existing issues to avoid duplicates
2. Use the latest version of SeekSweet
3. Verify the issue on both Windows and Linux if possible

When reporting a bug, include:
- **Description** - Clear description of the issue
- **Steps to Reproduce** - Exact steps to trigger the bug
- **Expected Behavior** - What should happen
- **Actual Behavior** - What actually happens
- **Environment** - OS, Python version, tool version
- **Logs** - Any relevant error messages or output
- **Screenshots** - If applicable

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When suggesting:
- **Use a clear title** - Describe the enhancement concisely
- **Provide detailed description** - Explain the motivation and use case
- **Show examples** - Include mockups or examples if applicable
- **Consider scope** - Keep enhancements focused and reasonable

### Pull Requests

#### Before You Start
1. **Fork the repository**
2. **Create a feature branch** - `git checkout -b feature/amazing-feature`
3. **Discuss major changes** - Open an issue first for big changes

#### Development Guidelines

**Code Style**
- Follow PEP 8 Python style guide
- Use 4 spaces for indentation (no tabs)
- Keep lines under 100 characters when reasonable
- Use descriptive variable and function names
- Add docstrings for all functions and classes

**Example:**
```python
def discover_services(target_ip: str, timeout: int = 5) -> dict:
    """
    Discover services running on target IP.
    
    Args:
        target_ip: IP address to scan
        timeout: Connection timeout in seconds
        
    Returns:
        dict: Dictionary of discovered services
    """
    # Implementation here
    pass
```

**Testing**
- Test on **both Windows and Linux** if modifying core functionality
- Verify all tools still work independently
- Test SeekSweet orchestrator with your changes
- Ensure CIDR expansion works correctly
- Check persistent tracking isn't broken

**Documentation**
- Update README.md if adding features
- Update CHANGELOG.md with your changes
- Update tool-specific documentation if applicable
- Include code comments for complex logic

**Commit Messages**
Use clear, descriptive commit messages:
```
Add SNMPv3 support to SNMPSeek

- Implement SNMPv3 authentication
- Add -v3 flag for version selection
- Update documentation with v3 examples
- Add error handling for auth failures

Fixes #123
```

#### Pull Request Process

1. **Update Documentation**
   - README.md for user-facing changes
   - CHANGELOG.md with your changes
   - Tool-specific docs if applicable

2. **Test Thoroughly**
   - Run affected tools independently
   - Test via SeekSweet orchestrator
   - Verify on Windows and Linux if possible

3. **Create Pull Request**
   - Use descriptive title
   - Reference related issues
   - Describe changes in detail
   - Include testing performed
   - Note any breaking changes

4. **Code Review**
   - Respond to feedback promptly
   - Make requested changes
   - Keep discussion professional and constructive

5. **Merge**
   - Maintainer will merge once approved
   - Delete your feature branch after merge

## 🎯 Good First Issues

Looking for where to start? Check issues labeled:
- `good first issue` - Simple fixes good for newcomers
- `help wanted` - Features we'd love help with
- `documentation` - Docs improvements needed

## 🛠️ Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/seeksweet.git
cd seeksweet

# Create feature branch
git checkout -b feature/my-feature

# Make changes and test
python seeksweet.py

# Run individual tool
cd dcseek
python dcseek.py -f ../iplist.txt -v

# Commit changes
git add .
git commit -m "Add my feature"
git push origin feature/my-feature
```

## 📋 Checklist for New Tools

If contributing a new tool:

- [ ] Follow naming convention: `*seek.py`
- [ ] Implement `find_ip_list()` from seek_utils
- [ ] Support `-v/--verbose` and `-q/--quiet` flags
- [ ] Generate standardized output files (`*list.txt`, `*_details.txt`)
- [ ] Add to SEEK_TOOLS list in seeksweet.py
- [ ] Include phase and priority in tool definition
- [ ] Create documentation (README.md, QUICKREF.md, SUMMARY.md)
- [ ] Add output files to .gitignore
- [ ] Test independently and via orchestrator
- [ ] Verify cross-platform compatibility

## 🔒 Security

### Reporting Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead, email: security@seeksweet.example.com (replace with actual contact)

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix if you have one

We'll respond within 48 hours and work with you on a fix.

### Security Best Practices

When contributing:
- Never include real credentials or API keys
- Avoid hardcoded passwords or secrets
- Sanitize user input
- Use secure defaults
- Follow principle of least privilege
- Document security considerations

## 📜 Code of Conduct

### Our Standards

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards others

### Unacceptable Behavior

- Harassment, trolling, or personal attacks
- Publishing others' private information
- Sexualized language or imagery
- Other conduct inappropriate for a professional setting

### Enforcement

Violations may result in:
- Warning
- Temporary ban
- Permanent ban

Report issues to: conduct@seeksweet.example.com (replace with actual contact)

## 🎓 Learning Resources

- [Python PEP 8 Style Guide](https://pep8.org/)
- [Git Branching Model](https://nvie.com/posts/a-successful-git-branching-model/)
- [Writing Good Commit Messages](https://chris.beams.io/posts/git-commit/)

## 💬 Questions?

- Open a GitHub Discussion for general questions
- Open an Issue for bugs or feature requests
- Check existing documentation first

## 🙏 Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Mentioned in relevant documentation

Thank you for helping make SeekSweet better! 🍬
