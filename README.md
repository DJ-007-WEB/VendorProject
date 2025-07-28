# 🥗 FreshConnect – Vendor-Supplier Management Platform

**FreshConnect** is a vendor-focused procurement platform designed for **street food entrepreneurs** to connect with **trusted suppliers**, manage their profiles, check daily prices, and handle their orders—all in one place.

The project uses **Flask** for backend development, **SQLite3** for data storage, and a responsive **Tailwind CSS** frontend interface.

---

## 📁 Project Structure


---

## ⚙️ Core Features

### 🌐 Frontend Pages
- **`index.html`**: Welcome page for vendors and suppliers.
- **`dashboard.html`**: Central hub for navigating between key functions.
- **`vendor-profile.html`**: View and edit vendor information like name, business type, location, and specialty.
- **`manage-products.html`**: Manage raw material listings and stock status.
- **`prices.html`**: Display current daily prices with trend indicators.
- **`suppliers.html`**: Discover verified raw material suppliers.
- **`vendor-orders.html`**: Track order history, including statuses like completed or pending.

### 🖥️ Backend (`hack1.py`)
- Built with **Python Flask**
- Powers all server-side routing and API integration
- Interfaces with `user_database.db` to:
  - Fetch vendor data
  - Display and edit profile info
  - Dynamically populate profile fields on frontend

---

## 🗄️ Database: `user_database.db`

- Powered by **SQLite3**
- Stores vendor data such as:
  - Owner name
  - Email
  - Phone number
  - Business details (type, location, specialty, years active)
- Integrated into Flask backend for real-time updates

---

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/freshconnect.git
cd freshconnect
