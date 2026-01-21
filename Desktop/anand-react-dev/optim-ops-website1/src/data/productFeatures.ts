import { ProductFeature } from '../types/Subscription';

export const productFeatures: Record<string, ProductFeature[]> = {
  healthcare: [
    {
      title: 'Patient Record Management',
      description: 'Comprehensive digital patient records with medical history, allergies, medications, and treatment plans.',
      example: 'Dr. Smith can instantly access John Doe\'s complete medical history, including his diabetes management plan and recent lab results, during a consultation.',
      planRequired: 'basic'
    },
    {
      title: 'Appointment Scheduling',
      description: 'Smart scheduling system with automated reminders, conflict detection, and patient self-booking portal.',
      example: 'Patients can book appointments online, receive SMS reminders, and the system automatically blocks conflicting time slots.',
      planRequired: 'basic'
    },
    {
      title: 'Medical Report Generation',
      description: 'Automated generation of medical reports, prescriptions, and discharge summaries with customizable templates.',
      example: 'Generate detailed discharge summaries for cardiac patients with pre-filled medication lists and follow-up instructions.',
      planRequired: 'standard'
    },
    {
      title: 'Billing & Insurance Integration',
      description: 'Seamless integration with insurance providers for claim processing and automated billing workflows.',
      example: 'Automatically submit insurance claims for procedures and track reimbursement status in real-time.',
      planRequired: 'standard'
    },
    {
      title: 'Advanced Analytics & Reporting',
      description: 'Comprehensive analytics on patient outcomes, treatment effectiveness, and operational efficiency.',
      example: 'Track patient satisfaction scores, treatment success rates, and identify trends in common diagnoses.',
      planRequired: 'pro'
    },
    {
      title: 'Telemedicine Integration',
      description: 'Built-in video consultation platform with secure patient communication and remote monitoring.',
      example: 'Conduct virtual consultations with patients, share screens for reviewing test results, and monitor chronic conditions remotely.',
      planRequired: 'pro'
    }
  ],
  tax: [
    {
      title: 'Lead Management System',
      description: 'Comprehensive lead tracking from initial contact to client conversion with automated follow-ups.',
      example: 'Track potential clients from their first inquiry, set automated reminders for follow-ups, and monitor conversion rates.',
      planRequired: 'basic'
    },
    {
      title: 'Client Account Management',
      description: 'Centralized client database with document storage, communication history, and service tracking.',
      example: 'Store all client documents, track service history, and maintain detailed notes from every interaction.',
      planRequired: 'basic'
    },
    {
      title: 'Task & Workflow Management',
      description: 'Automated task assignment and workflow management for tax preparation and filing processes.',
      example: 'Automatically assign tax preparation tasks based on complexity, track progress, and ensure deadlines are met.',
      planRequired: 'standard'
    },
    {
      title: 'GST Filing & Compliance',
      description: 'Automated GST return preparation, filing, and compliance tracking with real-time updates.',
      example: 'Generate GST returns automatically from transaction data, file electronically, and track compliance status.',
      planRequired: 'standard'
    },
    {
      title: 'Advanced Financial Analytics',
      description: 'Comprehensive financial analysis tools with custom reporting and business intelligence.',
      example: 'Generate detailed financial health reports for clients, identify tax-saving opportunities, and provide strategic advice.',
      planRequired: 'pro'
    },
    {
      title: 'Multi-Entity Management',
      description: 'Manage multiple business entities and complex corporate structures from a single dashboard.',
      example: 'Handle tax compliance for holding companies with multiple subsidiaries, each with different tax requirements.',
      planRequired: 'pro'
    }
  ],
  beauty: [
    {
      title: 'Online Booking System',
      description: 'Customer-facing booking portal with real-time availability, service selection, and staff preferences.',
      example: 'Customers can book hair appointments online, choose their preferred stylist, and receive confirmation emails.',
      planRequired: 'basic'
    },
    {
      title: 'Customer Profile Management',
      description: 'Detailed customer profiles with service history, preferences, allergies, and photo documentation.',
      example: 'Track customer\'s hair color history, skin sensitivities, and preferred service providers for personalized experiences.',
      planRequired: 'basic'
    },
    {
      title: 'Loyalty Program Management',
      description: 'Automated loyalty points system with rewards tracking and promotional campaign management.',
      example: 'Customers earn points for each visit, receive birthday discounts, and get notified about special promotions.',
      planRequired: 'standard'
    },
    {
      title: 'Inventory & Product Management',
      description: 'Track beauty products, supplies inventory, and automated reorder notifications.',
      example: 'Monitor hair product levels, get alerts when shampoo stock is low, and track product usage per service.',
      planRequired: 'standard'
    },
    {
      title: 'Advanced Customer Analytics',
      description: 'Customer behavior analysis, service popularity tracking, and revenue optimization insights.',
      example: 'Identify peak booking times, most popular services, and customer lifetime value to optimize operations.',
      planRequired: 'pro'
    },
    {
      title: 'Multi-Location Management',
      description: 'Centralized management of multiple salon locations with unified reporting and staff scheduling.',
      example: 'Manage 5 salon locations from one dashboard, transfer bookings between locations, and track performance.',
      planRequired: 'pro'
    }
  ],
  food: [
    {
      title: 'Menu Management System',
      description: 'Digital menu creation with pricing, ingredients, nutritional information, and seasonal updates.',
      example: 'Create digital menus with photos, update prices instantly across all platforms, and mark seasonal items.',
      planRequired: 'basic'
    },
    {
      title: 'Order Processing & POS',
      description: 'Integrated point-of-sale system with order tracking, kitchen display, and payment processing.',
      example: 'Take orders on tablets, send them directly to kitchen displays, and process payments with integrated card readers.',
      planRequired: 'basic'
    },
    {
      title: 'Inventory Management',
      description: 'Real-time inventory tracking with automated reorder points and supplier management.',
      example: 'Track ingredient usage, get alerts when tomatoes are running low, and automatically reorder from suppliers.',
      planRequired: 'standard'
    },
    {
      title: 'Customer Relationship Management',
      description: 'Customer profiles with order history, preferences, and targeted marketing campaigns.',
      example: 'Remember customer\'s favorite dishes, dietary restrictions, and send personalized promotional offers.',
      planRequired: 'standard'
    },
    {
      title: 'Advanced Analytics & Forecasting',
      description: 'Sales forecasting, menu performance analysis, and operational efficiency metrics.',
      example: 'Predict busy periods, identify best-selling items, and optimize staff scheduling based on historical data.',
      planRequired: 'pro'
    },
    {
      title: 'Multi-Channel Integration',
      description: 'Integration with delivery platforms, online ordering, and third-party services.',
      example: 'Sync menus with Uber Eats, manage orders from multiple platforms, and track delivery performance.',
      planRequired: 'pro'
    }
  ],
  manufacturing: [
    {
      title: 'Production Tracking',
      description: 'Real-time monitoring of production lines with quality control and efficiency metrics.',
      example: 'Track production output in real-time, monitor machine efficiency, and identify bottlenecks instantly.',
      planRequired: 'basic'
    },
    {
      title: 'Inventory Management',
      description: 'Raw materials and finished goods tracking with automated reorder points and supplier integration.',
      example: 'Monitor raw material levels, automatically reorder steel when inventory drops below threshold.',
      planRequired: 'basic'
    },
    {
      title: 'Quality Control System',
      description: 'Comprehensive quality assurance with inspection checklists, defect tracking, and compliance reporting.',
      example: 'Digital quality checklists for each production batch, track defect rates, and generate compliance reports.',
      planRequired: 'standard'
    },
    {
      title: 'Supply Chain Management',
      description: 'End-to-end supply chain visibility with supplier performance tracking and logistics optimization.',
      example: 'Track shipments from suppliers, monitor delivery performance, and optimize logistics routes.',
      planRequired: 'standard'
    },
    {
      title: 'Predictive Maintenance',
      description: 'AI-powered equipment maintenance scheduling with failure prediction and cost optimization.',
      example: 'Predict when machines need maintenance based on usage patterns, reducing unexpected downtime.',
      planRequired: 'pro'
    },
    {
      title: 'Advanced Production Analytics',
      description: 'Comprehensive production analytics with OEE calculation, trend analysis, and optimization recommendations.',
      example: 'Calculate Overall Equipment Effectiveness, identify improvement opportunities, and optimize production schedules.',
      planRequired: 'pro'
    }
  ],
  merchants: [
    {
      title: 'Sales Management',
      description: 'Comprehensive sales tracking with transaction history, payment processing, and receipt management.',
      example: 'Process sales transactions, track daily revenue, and generate detailed sales reports for tax purposes.',
      planRequired: 'basic'
    },
    {
      title: 'Inventory Control',
      description: 'Real-time inventory tracking with barcode scanning, stock alerts, and automated reordering.',
      example: 'Scan barcodes to update inventory, get alerts when products are low, and automatically reorder popular items.',
      planRequired: 'basic'
    },
    {
      title: 'Customer Analytics',
      description: 'Customer behavior analysis with purchase history, preferences, and loyalty program management.',
      example: 'Track customer purchase patterns, identify VIP customers, and create targeted marketing campaigns.',
      planRequired: 'standard'
    },
    {
      title: 'Multi-Channel Integration',
      description: 'Unified management of online and offline sales channels with synchronized inventory.',
      example: 'Manage both physical store and online shop inventory from one system, sync product availability.',
      planRequired: 'standard'
    },
    {
      title: 'Advanced Business Intelligence',
      description: 'Comprehensive business analytics with forecasting, trend analysis, and performance optimization.',
      example: 'Predict seasonal demand, analyze profit margins by product category, and optimize pricing strategies.',
      planRequired: 'pro'
    },
    {
      title: 'Enterprise Integration',
      description: 'Integration with accounting systems, CRM platforms, and third-party business tools.',
      example: 'Sync sales data with QuickBooks, integrate with Salesforce CRM, and connect to marketing automation tools.',
      planRequired: 'pro'
    }
  ]
};