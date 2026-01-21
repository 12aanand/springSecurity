export interface SubscriptionPlan {
  id: string;
  name: string;
  price: number;
  period: string;
  features: string[];
  popular?: boolean;
  description: string;
}

export interface UserSubscription {
  domainId: string;
  planId: string;
  status: 'active' | 'inactive' | 'trial';
  expiresAt: Date;
}

export interface ProductFeature {
  title: string;
  description: string;
  example: string;
  planRequired: string; // 'basic', 'standard', 'pro'
}