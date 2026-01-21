import { SubscriptionPlan } from '../types/Subscription';

export const subscriptionPlans: SubscriptionPlan[] = [
  {
    id: 'basic',
    name: 'Basic',
    price: 29,
    period: 'month',
    description: 'Perfect for small businesses getting started',
    features: [
      'Core functionality access',
      'Up to 100 records/transactions',
      'Basic reporting',
      'Email support',
      'Mobile app access',
      '1 user account'
    ]
  },
  {
    id: 'standard',
    name: 'Standard',
    price: 79,
    period: 'month',
    description: 'Ideal for growing businesses with advanced needs',
    popular: true,
    features: [
      'All Basic features',
      'Up to 1,000 records/transactions',
      'Advanced reporting & analytics',
      'Priority support',
      'API access',
      'Up to 5 user accounts',
      'Custom integrations',
      'Automated workflows'
    ]
  },
  {
    id: 'pro',
    name: 'Pro',
    price: 149,
    period: 'month',
    description: 'Enterprise-grade solution for large organizations',
    features: [
      'All Standard features',
      'Unlimited records/transactions',
      'Advanced AI insights',
      '24/7 dedicated support',
      'White-label options',
      'Unlimited user accounts',
      'Custom development',
      'Multi-location management',
      'Advanced security features'
    ]
  }
];