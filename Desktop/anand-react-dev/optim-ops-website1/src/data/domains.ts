import { 
  Heart, 
  Calculator, 
  Sparkles, 
  UtensilsCrossed, 
  Factory, 
  ShoppingBag 
} from 'lucide-react';
import { Domain } from '../types/Domain';

export const domains: Domain[] = [
  {
    id: 'healthcare',
    title: 'OPTIM OPS Healthcare',
    subtitle: 'Medical Operations',
    description: 'Comprehensive healthcare management system for patient records, appointments, and medical workflows.',
    icon: Heart,
    color: 'text-red-600',
    gradient: 'from-red-500 via-pink-500 to-rose-600',
    features: [
      'Patient record management',
      'Appointment scheduling',
      'Medical report generation',
      'Billing and insurance'
    ]
  },
  {
    id: 'tax',
    title: 'OPTIM OPS Tax & Advisory',
    subtitle: 'Financial Operations',
    description: 'Professional tax filing, accounting, and compliance tracking for businesses and individuals.',
    icon: Calculator,
    color: 'text-green-600',
    gradient: 'from-green-500 via-emerald-500 to-teal-600',
    features: [
      'Tax preparation and filing',
      'Accounting management',
      'Compliance tracking',
      'Financial reporting'
    ]
  },
  {
    id: 'beauty',
    title: 'OPTIM OPS Beauty & Grooming',
    subtitle: 'Wellness Operations',
    description: 'Complete salon and spa management with booking systems, customer profiles, and loyalty programs.',
    icon: Sparkles,
    color: 'text-purple-600',
    gradient: 'from-purple-500 via-violet-500 to-indigo-600',
    features: [
      'Online booking system',
      'Customer management',
      'Loyalty programs',
      'Service customization'
    ]
  },
  {
    id: 'food',
    title: 'OPTIM OPS Food Outlets',
    subtitle: 'Restaurant Operations',
    description: 'Full-service restaurant management including menu planning, order processing, and POS integration.',
    icon: UtensilsCrossed,
    color: 'text-orange-600',
    gradient: 'from-orange-500 via-amber-500 to-yellow-600',
    features: [
      'Menu management',
      'Order processing',
      'POS integration',
      'Inventory tracking'
    ]
  },
  {
    id: 'manufacturing',
    title: 'OPTIM OPS Manufacturing',
    subtitle: 'Production Operations',
    description: 'Industrial-grade manufacturing operations with production tracking and supply chain management.',
    icon: Factory,
    color: 'text-blue-600',
    gradient: 'from-blue-500 via-cyan-500 to-sky-600',
    features: [
      'Production tracking',
      'Inventory management',
      'Supply chain optimization',
      'Quality control'
    ]
  },
  {
    id: 'merchants',
    title: 'OPTIM OPS Merchants',
    subtitle: 'Retail Operations',
    description: 'Complete retail management solution with sales tracking, inventory control, and customer insights.',
    icon: ShoppingBag,
    color: 'text-indigo-600',
    gradient: 'from-indigo-500 via-blue-500 to-purple-600',
    features: [
      'Sales management',
      'Inventory control',
      'Customer analytics',
      'Multi-channel integration'
    ]
  }
];