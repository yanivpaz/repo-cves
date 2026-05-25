import * as mysql from 'mysql';
import * as pg from 'pg';

// Vulnerable Database Connection
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'test_db'
});

// VULNERABLE: Direct string concatenation in SQL query
export function getUserByIdVulnerable(userId: string): void {
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  connection.query(query, (error, results) => {
    if (error) {
      console.error('Query error:', error);
    } else {
      console.log('User found:', results);
    }
  });
}

// VULNERABLE: Template literals with user input
export function getProductByNameVulnerable(productName: string): void {
  const query = `SELECT * FROM products WHERE name = '${productName}'`;
  connection.query(query, (error, results) => {
    if (error) {
      console.error('Query error:', error);
    } else {
      console.log('Product found:', results);
    }
  });
}

// VULNERABLE: String concatenation with user-provided search term
export function searchOrdersVulnerable(searchTerm: string): void {
  const query = "SELECT * FROM orders WHERE status = '" + searchTerm + "' OR item_name = '" + searchTerm + "'";
  connection.query(query, (error, results) => {
    if (error) {
      console.error('Query error:', error);
    } else {
      console.log('Orders found:', results);
    }
  });
}

// VULNERABLE: Using sprintf or similar to construct SQL
export function getUserWithRoleVulnerable(userId: string, role: string): void {
  const userIdSanitized = userId.replace(/'/g, "''");
  const query = `SELECT * FROM users WHERE user_id = '${userIdSanitized}' AND role = '${role}'`;
  connection.query(query, (error, results) => {
    if (error) {
      console.error('Query error:', error);
    } else {
      console.log('User with role found:', results);
    }
  });
}

// VULNERABLE: Multiple concatenations
export function complexQueryVulnerable(firstName: string, lastName: string, email: string): void {
  const query = "INSERT INTO customers (first_name, last_name, email) VALUES ('" 
    + firstName + "', '" 
    + lastName + "', '" 
    + email + "')";
  connection.query(query, (error, results) => {
    if (error) {
      console.error('Insert error:', error);
    } else {
      console.log('Customer inserted');
    }
  });
}

// VULNERABLE: Using dynamic WHERE clause
export function filterUsersByConditionVulnerable(fieldName: string, fieldValue: string): void {
  const query = "SELECT * FROM users WHERE " + fieldName + " = '" + fieldValue + "'";
  connection.query(query, (error, results) => {
    if (error) {
      console.error('Query error:', error);
    } else {
      console.log('Filtered users:', results);
    }
  });
}

// VULNERABLE: PostgreSQL with string concatenation
const pgClient = new pg.Client({
  host: 'localhost',
  user: 'postgres',
  password: 'password',
  database: 'postgres_db'
});

export function pgGetUserVulnerable(userId: string): void {
  const query = 'SELECT * FROM users WHERE id = ' + userId;
  pgClient.query(query, (error, results) => {
    if (error) {
      console.error('Query error:', error);
    } else {
      console.log('User found:', results.rows);
    }
  });
}

// VULNERABLE: Using eval or similar (extreme vulnerability)
export function dynamicQueryVulnerable(userInput: string): void {
  const query = eval(`"SELECT * FROM users WHERE id = ${userInput}"`);
  connection.query(query, (error, results) => {
    if (error) {
      console.error('Query error:', error);
    } else {
      console.log('User found:', results);
    }
  });
}
