# CLAUDE.md

When creating Python extensions, follow these critical guidelines:

## Core Principles
- **Unique functionality**: Don't duplicate existing extensions
- **Security first**: Treat all HTTP message content as untrusted
- **Non-blocking**: Use background threads for slow operations (HTTP requests, file I/O)
- **Clean lifecycle**: Implement proper cleanup handlers for all resources

## Technical Requirements

### Threading
- Always use threads for slow operations
- Protect shared data

### Resource Management
- Release all resources in cleanup handlers
- Terminate background threads gracefully
- Close file handles and network connections
- Clean up temporary files

### Networking
- Use framework's HTTP methods, not `requests` or `urllib`
- Support upstream proxy settings
- Include offline fallbacks for external data

### Performance
- Don't hold long-term references to large objects
- Use generators/iterators for large datasets
- Implement pagination for history/sitemap access
- Use temporary file storage for persistent data

### UI Guidelines
- Parent all GUI elements to main application frame
- Handle exceptions in background threads explicitly
- Maintain UI responsiveness at all times

## Code Standards
- Python 3.8+ compatibility
- Type hints for public methods
- PEP 8 compliance
- Comprehensive docstrings
- Exception handling in all threads

## AI Extensions
- Use framework's AI API methods only
- Never require user API keys
- Route all AI traffic through platform infrastructure

## Remember
- Assume high-security environments (no internet)
- Support very large projects gracefully
- Support multi-monitor setups
- Document all dependencies clearly