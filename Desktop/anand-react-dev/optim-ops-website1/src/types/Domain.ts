import { DivideIcon as LucideIcon } from 'lucide-react';

export interface Domain {
  id: string;
  title: string;
  subtitle: string;
  description: string;
  icon: LucideIcon;
  color: string;
  gradient: string;
  features: string[];
}