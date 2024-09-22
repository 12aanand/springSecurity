#Spring Security with JWT Authentication
This repository demonstrates how to implement JWT-based authentication using Spring Security. The project provides secure APIs by authenticating users and generating JWTs for subsequent API requests.

##Features
JWT Authentication: Secure APIs using stateless authentication with JWTs.
User Authentication: Validate user credentials and issue JWT tokens upon successful login.
Token-Based Authorization: Protect endpoints by verifying JWT tokens in the request headers.
Role-Based Access Control (RBAC): Restrict API access based on user roles.
Password Encryption: Secure user credentials using bcrypt password encoding.
Technologies Used
Spring Boot: Framework to simplify Spring-based Java applications.
Spring Security: Security framework to handle authentication and authorization.
JWT (JSON Web Token): Used for stateless authentication.
Maven: Project management and build automation tool.

##How It Works
User Login: Users send a POST request with their credentials (username & password) to /login. Upon successful authentication, the server responds with a JWT token.

JWT Token Usage: Clients must include the JWT token in the Authorization header (as Bearer <token>) for subsequent requests to access protected resources.

Token Verification: For each request, the JWT token is validated, and the user's identity and role are extracted from the token.
