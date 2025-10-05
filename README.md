# Twitter Cookie Manager 🍪

A beautiful web application for securely storing and managing Twitter cookies with MongoDB integration.

## Features ✨

- **Cookie Extraction**: Upload cookie JSON and extract name/value pairs
- **User Management**: Store cookies with username in MongoDB
- **Beautiful UI**: Modern gradient design with responsive layout
- **Real-time Stats**: Live statistics about stored users and cookies
- **MongoDB Integration**: Secure storage with proper schema validation
- **Error Handling**: Comprehensive error handling and user feedback

## Setup Instructions 🚀

### Prerequisites
- Node.js (v14 or higher)
- MongoDB (local or MongoDB Atlas)

### Installation

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Configure Environment:**
   - Update `.env` file with your MongoDB connection string
   - The current setup uses MongoDB Atlas (already configured)

3. **Start the application:**
   ```bash
   npm start
   ```
   
   For development with auto-reload:
   ```bash
   npm run dev
   ```

4. **Access the application:**
   Open your browser and navigate to `http://localhost:3000`

## API Endpoints 📡

### POST `/api/upload-cookie`
Extract name and value from cookie JSON array
```json
{
  "cookieData": [
    {
      "name": "cookie_name",
      "value": "cookie_value",
      "domain": ".x.com",
      // ... other cookie properties
    }
  ]
}
```

### POST `/api/update-cookie`
Store cookies with username in MongoDB
```json
{
  "username": "twitter_username",
  "cookieData": "[{...cookie_array...}]" // JSON string or array
}
```

### GET `/api/user/:username`
Retrieve user's stored cookies

### GET `/api/users`
Get all users with basic stats

## Usage Guide 📖

### Form 1: Extract Cookie Data
1. Paste your cookie JSON array in the textarea
2. Click "Extract Cookie Data" to process
3. View extracted name/value pairs in the preview

### Form 2: Store User Cookies
1. Enter a username
2. Paste cookie JSON array
3. Click "Store Cookies" to save to database
4. View confirmation with cookie count and timestamp

## Database Schema 🗄️

```javascript
{
  username: String (unique),
  cookies: [
    {
      domain: String,
      name: String,
      value: String,
      // ... other cookie properties
    }
  ],
  createdAt: Date,
  updatedAt: Date
}
```

## Sample Cookie Data 📝

The application comes pre-loaded with sample Twitter cookie data for testing. You can replace this with your actual cookie data.

## Security Notes 🔒

- Cookies are stored securely in MongoDB
- Environment variables protect sensitive configuration
- Input validation prevents malicious data
- CORS enabled for API access

## Troubleshooting 🔧

### MongoDB Connection Issues
- Verify your MongoDB URI in `.env`
- Check network connectivity for MongoDB Atlas
- Ensure proper credentials and database permissions

### Application Errors
- Check console logs for detailed error messages
- Verify JSON format for cookie data
- Ensure all required fields are provided

## Development 👨‍💻

The application uses:
- **Backend**: Node.js, Express.js, Mongoose
- **Frontend**: Vanilla HTML, CSS, JavaScript
- **Database**: MongoDB with Mongoose ODM
- **Styling**: Modern CSS with gradients and animations

## Contributing 🤝

Feel free to submit issues and enhancement requests!

## License 📄

ISC License