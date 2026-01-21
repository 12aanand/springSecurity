export interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  assignedDomains: string[];
  avatar?: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
}