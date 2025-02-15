// server.js
const express = require("express");
const { graphqlHTTP } = require("express-graphql");
const { buildSchema } = require("graphql");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// --- Mongoose Models Setup ---

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email:    { type: String, required: true, unique: true },
    password: { type: String, required: true }, // will be stored encrypted
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now }
});
const User = mongoose.model("User", userSchema);

// Employee Schema
const employeeSchema = new mongoose.Schema({
    first_name: { type: String, required: true },
    last_name:  { type: String, required: true },
    email:      { type: String, required: true, unique: true },
    gender:     { type: String, enum: ["Male", "Female", "Other"] },
    designation:{ type: String, required: true },
    salary:     { type: Number, required: true, min: 1000 },
    date_of_joining: { type: Date, required: true },
    department: { type: String, required: true },
    employee_photo: { type: String },
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now }
});
const Employee = mongoose.model("Employee", employeeSchema);

// --- GraphQL Schema Definition ---

const schema = buildSchema(`
  type User {
    id: ID!
    username: String!
    email: String!
    created_at: String
    updated_at: String
  }
  
  type Employee {
    id: ID!
    first_name: String!
    last_name: String!
    email: String!
    gender: String
    designation: String!
    salary: Float!
    date_of_joining: String!
    department: String!
    employee_photo: String
    created_at: String
    updated_at: String
  }
  
  type LoginResponse {
    success: Boolean!
    token: String
    message: String
  }
  
  type UserResponse {
    success: Boolean!
    user: User
    message: String
  }
  
  type EmployeeResponse {
    success: Boolean!
    employee: Employee
    message: String
  }
  
  type DeleteResponse {
    success: Boolean!
    message: String
  }
  
  input UpdateEmployeeInput {
    first_name: String
    last_name: String
    email: String
    gender: String
    designation: String
    salary: Float
    date_of_joining: String
    department: String
    employee_photo: String
  }
  
  type Query {
    # Login using either username or email along with password
    login(usernameOrEmail: String!, password: String!): LoginResponse!
    
    # Get all employees
    getAllEmployees: [Employee]
    
    # Search employee by employee id (eid)
    searchEmployeeByEid(eid: ID!): Employee
    
    # Search employee by designation or department (at least one required)
    searchEmployeeByDesignationOrDepartment(designation: String, department: String): [Employee]
  }
  
  type Mutation {
    # Signup mutation to create a new user account
    signup(username: String!, email: String!, password: String!): UserResponse!
    
    # Add new employee
    addNewEmployee(
      first_name: String!, 
      last_name: String!, 
      email: String!, 
      gender: String, 
      designation: String!, 
      salary: Float!, 
      date_of_joining: String!, 
      department: String!, 
      employee_photo: String
    ): EmployeeResponse!
    
    # Update employee details by employee id
    updateEmployeeByEid(eid: ID!, input: UpdateEmployeeInput!): EmployeeResponse!
    
    # Delete employee by employee id
    deleteEmployeeByEid(eid: ID!): DeleteResponse!
  }
`);

// --- GraphQL Resolvers Implementation ---

const resolvers = {
    // Mutation: Signup a new user
    signup: async ({ username, email, password }) => {
        try {
            if (!username || !email || !password) {
                return { success: false, message: "All fields are required." };
            }

            // Check if username or email already exists
            const existingUser = await User.findOne({ $or: [{ username }, { email }] });
            if (existingUser) {
                return { success: false, message: "Username or email already exists." };
            }

            // Hash the password properly
            const saltRounds = 10; // Standard is 10
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            const user = new User({
                username,
                email,
                password: hashedPassword,
                created_at: new Date(),
                updated_at: new Date(),
            });

            await user.save();

            return {
                success: true,
                user: {
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    created_at: user.created_at.toISOString(),
                    updated_at: user.updated_at.toISOString(),
                },
                message: "User created successfully.",
            };
        } catch (err) {
            return { success: false, message: err.message };
        }
    },

    // Query: Login user using username or email and password
    login: async ({ usernameOrEmail, password }) => {
        try {
            // Find user by username or email
            const user = await User.findOne({
                $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
            });
            if (!user) {
                return { success: false, message: "User not found." };
            }
            // Compare password
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return { success: false, message: "Invalid credentials." };
            }
            // Sign a JWT (replace 'your_jwt_secret' with your secret key)
            const token = jwt.sign({ userId: user._id }, "your_jwt_secret", {
                expiresIn: "1h"
            });
            return { success: true, token, message: "Login successful." };
        } catch (err) {
            return { success: false, message: err.message };
        }
    },

    // Query: Get all employees
    getAllEmployees: async () => {
        try {
            const employees = await Employee.find();
            return employees.map(emp => ({
                id: emp._id,
                first_name: emp.first_name,
                last_name: emp.last_name,
                email: emp.email,
                gender: emp.gender,
                designation: emp.designation,
                salary: emp.salary,
                date_of_joining: emp.date_of_joining.toISOString(),
                department: emp.department,
                employee_photo: emp.employee_photo,
                created_at: emp.created_at.toISOString(),
                updated_at: emp.updated_at.toISOString()
            }));
        } catch (err) {
            throw new Error(err.message);
        }
    },

    // Query: Search employee by employee id (eid)
    searchEmployeeByEid: async ({ eid }) => {
        try {
            const emp = await Employee.findById(eid);
            if (!emp) return null;
            return {
                id: emp._id,
                first_name: emp.first_name,
                last_name: emp.last_name,
                email: emp.email,
                gender: emp.gender,
                designation: emp.designation,
                salary: emp.salary,
                date_of_joining: emp.date_of_joining.toISOString(),
                department: emp.department,
                employee_photo: emp.employee_photo,
                created_at: emp.created_at.toISOString(),
                updated_at: emp.updated_at.toISOString()
            };
        } catch (err) {
            throw new Error(err.message);
        }
    },

    // Mutation: Add new employee
    addNewEmployee: async (args) => {
        try {
            // Validate salary constraint (>=1000) is handled by Mongoose but can be re-checked
            if (args.salary < 1000) {
                return {
                    success: false,
                    message: "Salary must be at least 1000."
                };
            }
            const emp = new Employee({
                first_name: args.first_name,
                last_name: args.last_name,
                email: args.email,
                gender: args.gender,
                designation: args.designation,
                salary: args.salary,
                date_of_joining: new Date(args.date_of_joining),
                department: args.department,
                employee_photo: args.employee_photo
            });
            await emp.save();
            return {
                success: true,
                employee: {
                    id: emp._id,
                    first_name: emp.first_name,
                    last_name: emp.last_name,
                    email: emp.email,
                    gender: emp.gender,
                    designation: emp.designation,
                    salary: emp.salary,
                    date_of_joining: emp.date_of_joining.toISOString(),
                    department: emp.department,
                    employee_photo: emp.employee_photo,
                    created_at: emp.created_at.toISOString(),
                    updated_at: emp.updated_at.toISOString()
                },
                message: "Employee added successfully."
            };
        } catch (err) {
            return { success: false, message: err.message };
        }
    },

    // Mutation: Update employee by employee id (eid)
    updateEmployeeByEid: async ({ eid, input }) => {
        try {
            const emp = await Employee.findById(eid);
            if (!emp) {
                return { success: false, message: "Employee not found." };
            }
            // Update allowed fields only if provided in the input
            Object.keys(input).forEach(key => {
                // Special handling for date fields
                if (key === "date_of_joining" && input[key]) {
                    emp[key] = new Date(input[key]);
                } else if (input[key] !== undefined) {
                    emp[key] = input[key];
                }
            });
            emp.updated_at = new Date();
            await emp.save();
            return {
                success: true,
                employee: {
                    id: emp._id,
                    first_name: emp.first_name,
                    last_name: emp.last_name,
                    email: emp.email,
                    gender: emp.gender,
                    designation: emp.designation,
                    salary: emp.salary,
                    date_of_joining: emp.date_of_joining.toISOString(),
                    department: emp.department,
                    employee_photo: emp.employee_photo,
                    created_at: emp.created_at.toISOString(),
                    updated_at: emp.updated_at.toISOString()
                },
                message: "Employee updated successfully."
            };
        } catch (err) {
            return { success: false, message: err.message };
        }
    },

    // Mutation: Delete employee by employee id (eid)
    deleteEmployeeByEid: async ({ eid }) => {
        try {
            const emp = await Employee.findByIdAndDelete(eid);
            if (!emp) {
                return { success: false, message: "Employee not found." };
            }
            return { success: true, message: "Employee deleted successfully." };
        } catch (err) {
            return { success: false, message: err.message };
        }
    },

    // Query: Search employee by designation or department
    searchEmployeeByDesignationOrDepartment: async ({ designation, department }) => {
        try {
            // At least one filter should be provided
            if (!designation && !department) {
                throw new Error("Please provide either designation or department to search.");
            }
            const filter = {};
            if (designation) filter.designation = designation;
            if (department) filter.department = department;
            const employees = await Employee.find(filter);
            return employees.map(emp => ({
                id: emp._id,
                first_name: emp.first_name,
                last_name: emp.last_name,
                email: emp.email,
                gender: emp.gender,
                designation: emp.designation,
                salary: emp.salary,
                date_of_joining: emp.date_of_joining.toISOString(),
                department: emp.department,
                employee_photo: emp.employee_photo,
                created_at: emp.created_at.toISOString(),
                updated_at: emp.updated_at.toISOString()
            }));
        } catch (err) {
            throw new Error(err.message);
        }
    }
};

// --- Connect to MongoDB ---
mongoose
    .connect("mongodb://localhost:27017/comp3133__101468805_assigment1", {
        useNewUrlParser: true,
        useUnifiedTopology: true
    })
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.error(err));

// --- Express Server Setup ---
const app = express();

// For a real application, you could add express-validator middleware here
// before the /graphql endpoint to validate incoming requests

app.use(
    "/graphql",
    graphqlHTTP({
        schema,
        rootValue: resolvers,
        graphiql: true, // enables GraphiQL interactive editor
        customFormatErrorFn: err => {
            return { message: err.message, locations: err.locations, stack: err.stack };
        }
    })
);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
