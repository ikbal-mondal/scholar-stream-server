# 🎓 Scholarship Management System – Backend (Node.js + Express + MongoDB)

A complete backend API for managing scholarships, student applications, reviews, secure authentication, payments (Stripe), admin analytics, and contact inquiries.  
The system supports **Students**, **Moderators**, and **Admins** with role-based permissions.

---

## 🚀 Features

### 🔐 Authentication & User Management
- Register student profiles
- Firebase login → Backend JWT generation
- JWT-based authentication with role protection
- Update/Edit profile
- Admin controls:
  - View all users
  - Update user role (Student / Moderator / Admin)
  - Delete users

---

### 🎓 Scholarship Management
- Create, Read, Update, Delete (CRUD)
- Latest scholarships endpoint
- Full search and filtering with pagination
- Fields include:
  - Name, University, Description, Category, Degree
  - Fees, Deadlines, Eligibility, Documents
  - World rank, Country, City

---

### 📝 Application System
- Students can apply for scholarships
- Moderators/Admins:
  - Approve / Reject / Complete applications
  - Provide feedback
- Students can view their own applications
- Global application list (moderator/admin)

---

### ⭐ Reviews System
- Students can add/update/delete reviews
- Fetch reviews for a scholarship
- Moderators/Admins can delete inappropriate content

---

### 💳 Payments (Stripe)
Supports:
- Payment Intents  
- Checkout Sessions  
- Webhooks for payment confirmation  
- Automatic update of application status after successful payment

---

### 📊 Admin Analytics
- Total Users, Scholarships, Applications, Paid Applications
- Applications by:
  - University
  - Category
  - Top applied scholarships

---

### 📬 Contact Inquiry System
- Save contact form messages
- View all inquiries (admin side)
- Delete or view specific message

---

## 🛠️ Tech Stack

| Technology | Purpose |
|-----------|---------|
| **Node.js + Express.js** | Backend framework |
| **MongoDB** | Database |
| **JWT** | Authentication |
| **Firebase Admin** | Verify client Firebase login token |
| **Stripe** | Payments |
| **CORS** | API access |
| **dotenv** | Environment variables |



