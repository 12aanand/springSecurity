import { 
  Heart, 
  Users, 
  Calendar, 
  DollarSign, 
  TrendingUp, 
  Package, 
  ShoppingCart,
  Star,
  Activity,
  FileText,
  AlertCircle,
  Clock,
  Award,
  Target,
  BarChart3
} from 'lucide-react';

interface Widget {
  title: string;
  value: string;
  change: string;
  trend: 'up' | 'down';
  icon: React.ReactNode;
  color: string;
  gradient: string;
}

export const getWidgetsForDomain = (domainId: string): Widget[] => {
  const baseWidgets: Record<string, Widget[]> = {
    healthcare: [
      {
        title: 'Total Patients',
        value: '2,847',
        change: '+12%',
        trend: 'up',
        icon: <Users className="w-6 h-6 text-white" />,
        color: 'text-red-600',
        gradient: 'from-red-500 via-pink-500 to-rose-600'
      },
      {
        title: 'Appointments Today',
        value: '47',
        change: '+5%',
        trend: 'up',
        icon: <Calendar className="w-6 h-6 text-white" />,
        color: 'text-blue-600',
        gradient: 'from-blue-500 via-cyan-500 to-sky-600'
      },
      {
        title: 'Monthly Revenue',
        value: '$89,240',
        change: '+18%',
        trend: 'up',
        icon: <DollarSign className="w-6 h-6 text-white" />,
        color: 'text-green-600',
        gradient: 'from-green-500 via-emerald-500 to-teal-600'
      },
      {
        title: 'Patient Satisfaction',
        value: '94.2%',
        change: '+2%',
        trend: 'up',
        icon: <Heart className="w-6 h-6 text-white" />,
        color: 'text-pink-600',
        gradient: 'from-pink-500 via-rose-500 to-red-600'
      },
      {
        title: 'Emergency Cases',
        value: '8',
        change: '-15%',
        trend: 'down',
        icon: <AlertCircle className="w-6 h-6 text-white" />,
        color: 'text-orange-600',
        gradient: 'from-orange-500 via-amber-500 to-yellow-600'
      },
      {
        title: 'Average Wait Time',
        value: '12 min',
        change: '-8%',
        trend: 'down',
        icon: <Clock className="w-6 h-6 text-white" />,
        color: 'text-indigo-600',
        gradient: 'from-indigo-500 via-purple-500 to-violet-600'
      }
    ],
    tax: [
      {
        title: 'Total Leads',
        value: '1,847',
        change: '+15%',
        trend: 'up',
        icon: <Users className="w-6 h-6 text-white" />,
        color: 'text-blue-600',
        gradient: 'from-blue-500 via-cyan-500 to-sky-600'
      },
      {
        title: 'Active Accounts',
        value: '456',
        change: '+12%',
        trend: 'up',
        icon: <FileText className="w-6 h-6 text-white" />,
        color: 'text-green-600',
        gradient: 'from-green-500 via-emerald-500 to-teal-600'
      },
      {
        title: 'Pending Tasks',
        value: '89',
        change: '-8%',
        trend: 'down',
        icon: <AlertCircle className="w-6 h-6 text-white" />,
        color: 'text-orange-600',
        gradient: 'from-orange-500 via-amber-500 to-yellow-600'
      },
      {
        title: 'Active Workflows',
        value: '23',
        change: '+5%',
        trend: 'up',
        icon: <Activity className="w-6 h-6 text-white" />,
        color: 'text-purple-600',
        gradient: 'from-purple-500 via-violet-500 to-indigo-600'
      },
      {
        title: 'GST Returns Filed',
        value: '342',
        change: '+18%',
        trend: 'up',
        icon: <FileText className="w-6 h-6 text-white" />,
        color: 'text-indigo-600',
        gradient: 'from-indigo-500 via-blue-500 to-purple-600'
      },
      {
        title: 'Monthly Revenue',
        value: '$156,890',
        change: '+22%',
        trend: 'up',
        icon: <DollarSign className="w-6 h-6 text-white" />,
        color: 'text-red-600',
        gradient: 'from-red-500 via-pink-500 to-rose-600'
      }
    ],
    beauty: [
      {
        title: 'Today\'s Bookings',
        value: '67',
        change: '+15%',
        trend: 'up',
        icon: <Calendar className="w-6 h-6 text-white" />,
        color: 'text-purple-600',
        gradient: 'from-purple-500 via-violet-500 to-indigo-600'
      },
      {
        title: 'Active Members',
        value: '3,456',
        change: '+9%',
        trend: 'up',
        icon: <Users className="w-6 h-6 text-white" />,
        color: 'text-pink-600',
        gradient: 'from-pink-500 via-rose-500 to-red-600'
      },
      {
        title: 'Daily Revenue',
        value: '$8,920',
        change: '+12%',
        trend: 'up',
        icon: <DollarSign className="w-6 h-6 text-white" />,
        color: 'text-green-600',
        gradient: 'from-green-500 via-emerald-500 to-teal-600'
      },
      {
        title: 'Service Rating',
        value: '4.9/5',
        change: '+0.1',
        trend: 'up',
        icon: <Star className="w-6 h-6 text-white" />,
        color: 'text-yellow-600',
        gradient: 'from-yellow-500 via-amber-500 to-orange-600'
      },
      {
        title: 'Loyalty Points Used',
        value: '12,450',
        change: '+25%',
        trend: 'up',
        icon: <Award className="w-6 h-6 text-white" />,
        color: 'text-indigo-600',
        gradient: 'from-indigo-500 via-blue-500 to-purple-600'
      },
      {
        title: 'Staff Utilization',
        value: '87%',
        change: '+3%',
        trend: 'up',
        icon: <Activity className="w-6 h-6 text-white" />,
        color: 'text-cyan-600',
        gradient: 'from-cyan-500 via-teal-500 to-blue-600'
      }
    ],
    food: [
      {
        title: 'Today\'s Orders',
        value: '342',
        change: '+18%',
        trend: 'up',
        icon: <ShoppingCart className="w-6 h-6 text-white" />,
        color: 'text-orange-600',
        gradient: 'from-orange-500 via-amber-500 to-yellow-600'
      },
      {
        title: 'Daily Revenue',
        value: '$12,840',
        change: '+22%',
        trend: 'up',
        icon: <DollarSign className="w-6 h-6 text-white" />,
        color: 'text-green-600',
        gradient: 'from-green-500 via-emerald-500 to-teal-600'
      },
      {
        title: 'Average Order Value',
        value: '$37.52',
        change: '+5%',
        trend: 'up',
        icon: <TrendingUp className="w-6 h-6 text-white" />,
        color: 'text-blue-600',
        gradient: 'from-blue-500 via-cyan-500 to-sky-600'
      },
      {
        title: 'Customer Rating',
        value: '4.7/5',
        change: '+0.2',
        trend: 'up',
        icon: <Star className="w-6 h-6 text-white" />,
        color: 'text-yellow-600',
        gradient: 'from-yellow-500 via-amber-500 to-orange-600'
      },
      {
        title: 'Inventory Items',
        value: '156',
        change: '-3%',
        trend: 'down',
        icon: <Package className="w-6 h-6 text-white" />,
        color: 'text-purple-600',
        gradient: 'from-purple-500 via-violet-500 to-indigo-600'
      },
      {
        title: 'Table Turnover',
        value: '3.2x',
        change: '+8%',
        trend: 'up',
        icon: <Activity className="w-6 h-6 text-white" />,
        color: 'text-red-600',
        gradient: 'from-red-500 via-pink-500 to-rose-600'
      }
    ],
    manufacturing: [
      {
        title: 'Production Output',
        value: '4,892',
        change: '+14%',
        trend: 'up',
        icon: <BarChart3 className="w-6 h-6 text-white" />,
        color: 'text-blue-600',
        gradient: 'from-blue-500 via-cyan-500 to-sky-600'
      },
      {
        title: 'Efficiency Rate',
        value: '89.3%',
        change: '+2%',
        trend: 'up',
        icon: <TrendingUp className="w-6 h-6 text-white" />,
        color: 'text-green-600',
        gradient: 'from-green-500 via-emerald-500 to-teal-600'
      },
      {
        title: 'Quality Score',
        value: '96.8%',
        change: '+1%',
        trend: 'up',
        icon: <Award className="w-6 h-6 text-white" />,
        color: 'text-purple-600',
        gradient: 'from-purple-500 via-violet-500 to-indigo-600'
      },
      {
        title: 'Active Workers',
        value: '284',
        change: '+3%',
        trend: 'up',
        icon: <Users className="w-6 h-6 text-white" />,
        color: 'text-orange-600',
        gradient: 'from-orange-500 via-amber-500 to-yellow-600'
      },
      {
        title: 'Equipment Downtime',
        value: '2.1%',
        change: '-15%',
        trend: 'down',
        icon: <AlertCircle className="w-6 h-6 text-white" />,
        color: 'text-red-600',
        gradient: 'from-red-500 via-pink-500 to-rose-600'
      },
      {
        title: 'Inventory Value',
        value: '$890K',
        change: '+7%',
        trend: 'up',
        icon: <Package className="w-6 h-6 text-white" />,
        color: 'text-indigo-600',
        gradient: 'from-indigo-500 via-blue-500 to-purple-600'
      }
    ],
    merchants: [
      {
        title: 'Total Sales',
        value: '$45,280',
        change: '+16%',
        trend: 'up',
        icon: <DollarSign className="w-6 h-6 text-white" />,
        color: 'text-green-600',
        gradient: 'from-green-500 via-emerald-500 to-teal-600'
      },
      {
        title: 'Orders Today',
        value: '187',
        change: '+24%',
        trend: 'up',
        icon: <ShoppingCart className="w-6 h-6 text-white" />,
        color: 'text-blue-600',
        gradient: 'from-blue-500 via-cyan-500 to-sky-600'
      },
      {
        title: 'Active Customers',
        value: '2,156',
        change: '+11%',
        trend: 'up',
        icon: <Users className="w-6 h-6 text-white" />,
        color: 'text-purple-600',
        gradient: 'from-purple-500 via-violet-500 to-indigo-600'
      },
      {
        title: 'Conversion Rate',
        value: '3.8%',
        change: '+0.5%',
        trend: 'up',
        icon: <Target className="w-6 h-6 text-white" />,
        color: 'text-orange-600',
        gradient: 'from-orange-500 via-amber-500 to-yellow-600'
      },
      {
        title: 'Inventory Items',
        value: '1,847',
        change: '+5%',
        trend: 'up',
        icon: <Package className="w-6 h-6 text-white" />,
        color: 'text-red-600',
        gradient: 'from-red-500 via-pink-500 to-rose-600'
      },
      {
        title: 'Customer Rating',
        value: '4.6/5',
        change: '+0.1',
        trend: 'up',
        icon: <Star className="w-6 h-6 text-white" />,
        color: 'text-yellow-600',
        gradient: 'from-yellow-500 via-amber-500 to-orange-600'
      }
    ]
  };

  return baseWidgets[domainId] || [];
};