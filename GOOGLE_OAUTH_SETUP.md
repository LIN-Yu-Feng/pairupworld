# Google OAuth Setup Instructions

To enable Google login functionality for your PairUp application, you need to set up Google OAuth credentials. Follow these steps:

## Step 1: Create a Google Cloud Project

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Click "Select a project" and then "New Project"
3. Give your project a name (e.g., "PairUp Application")
4. Click "Create"

## Step 2: Enable Google APIs

1. In your project dashboard, go to "APIs & Services" > "Library"
2. Search for and enable the following APIs:
   - **Google+ API** (for user profile information)
   - **Google People API** (for user details)

## Step 3: Create OAuth 2.0 Credentials

1. Go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "OAuth client ID"
3. If prompted, configure the OAuth consent screen:
   - Choose "External" user type
   - Fill in the application name: "PairUp"
   - Add your email as a developer contact
   - Add scopes: `profile` and `email`
4. For application type, select "Web application"
5. Give it a name (e.g., "PairUp Web Client")
6. Add authorized redirect URIs:
   - `http://localhost:3000/auth/google/callback`
   - If you deploy to production, add your production URL here too

## Step 4: Configure Your Application

1. Copy the **Client ID** and **Client Secret** from the credentials page
2. Open the `config.env` file in your project root
3. Replace the placeholder values:
   ```env
   GOOGLE_CLIENT_ID=your_actual_client_id_here
   GOOGLE_CLIENT_SECRET=your_actual_client_secret_here
   ```

## Step 5: Test the Integration

1. Start your server: `npm start`
2. Navigate to `http://localhost:3000/login.html`
3. Click the "Continue with Google" button
4. You should be redirected to Google's authentication page
5. After successful authentication, you'll be redirected back to your app

## Troubleshooting

### Common Issues:

1. **"redirect_uri_mismatch" error**:
   - Make sure the redirect URI in Google Console exactly matches: `http://localhost:3000/auth/google/callback`
   - Don't include trailing slashes

2. **"OAuth consent screen" issues**:
   - Make sure you've configured the consent screen in Google Console
   - Add your email as a test user if the app is in development mode

3. **"invalid_client" error**:
   - Double-check your Client ID and Client Secret in the config.env file
   - Make sure there are no extra spaces or characters

4. **App won't start**:
   - Make sure you've installed the new dependencies: `npm install`
   - Check that your config.env file is properly formatted

### Development Notes:

- The app currently supports both email/password authentication and Google OAuth
- Google users are automatically created in the database with verified status
- If a user with the same email exists, the Google ID is linked to the existing account
- All authentication methods use JWT tokens for session management

## Security Notes for Production:

1. Change all default secrets in config.env
2. Use HTTPS in production (update OAuth callback URLs accordingly)
3. Set proper CORS origins for your production domain
4. Consider implementing additional security measures like rate limiting for OAuth endpoints
