# Kyroshield Backend

This is the backend server for Kyroshield website, deployed on Railway.

## Environment Variables Required

1. **EMAIL_HOST** - SMTP server (e.g., smtp.gmail.com)
2. **EMAIL_PORT** - Port (e.g., 587)
3. **EMAIL_USER** - Your email address
4. **EMAIL_PASSWORD** - App-specific password
5. **EMAIL_FROM** - Sender email
6. **EMAIL_TO** - Admin email for notifications

## API Endpoints

- `GET /api/health` - Health check
- `POST /api/send-email` - Submit quote form
- `POST /api/test-email` - Test email configuration

## Deploying to Railway

1. Push to GitHub
2. Connect repository to Railway
3. Add environment variables
4. Deploy