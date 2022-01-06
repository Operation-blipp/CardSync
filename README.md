# CardSync
Utility to sync NFC cards with a server 

[Link to protocol](./protocol.md)

Deployment server (WSGI) run using gunicorn. Configuration settings are read from `settings.py` through
`gunicorn.py` by running `gunicorn -c gunicorn.py "server:create_app()"`