import { useState } from 'react'
import { useRouter } from 'next/router'
import Link from 'next/link'
import {
  Shield, Menu, User, LogOut, Settings,
  LayoutDashboard, Server, Scan, Bug,
  Code2, Users, History, Link as LinkIcon,
  ChevronLeft, ChevronRight,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Separator } from '@/components/ui/separator'
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { ThemeToggle } from '@/components/theme-toggle'
import { cn } from '@/lib/utils'
import authService from '@/lib/services/authService'

const navItems = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/assets', label: 'Assets', icon: Server },
  { path: '/scans', label: 'Scans', icon: Scan },
  { path: '/vulnerabilities', label: 'Vulnérabilités', icon: Bug },
  { path: '/scripts', label: 'Scripts', icon: Code2 },
  { path: '/groups', label: 'Groupes', icon: Users },
  { path: '/analysis-history', label: 'Historique IA', icon: History },
  { path: '/webhooks', label: 'Webhooks', icon: LinkIcon },
]

function NavItem({ item, isActive, collapsed, onClick }) {
  const Icon = item.icon
  return (
    <Link href={item.path} passHref legacyBehavior>
      <a
        onClick={onClick}
        className={cn(
          'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all hover:bg-accent hover:text-accent-foreground',
          isActive
            ? 'bg-accent text-accent-foreground'
            : 'text-muted-foreground',
          collapsed && 'justify-center px-2'
        )}
        title={collapsed ? item.label : undefined}
      >
        <Icon className="h-5 w-5 shrink-0" />
        {!collapsed && <span>{item.label}</span>}
      </a>
    </Link>
  )
}

function SidebarContent({ collapsed, onNavClick }) {
  const router = useRouter()
  const isActive = (path) => {
    if (path === '/') return router.pathname === '/'
    return router.pathname === path || router.pathname.startsWith(`${path}/`)
  }

  return (
    <div className="flex h-full flex-col gap-2">
      <div className={cn('flex items-center gap-2 py-4 px-3', collapsed && 'justify-center px-2')}>
        <Shield className="h-6 w-6 shrink-0 text-primary" />
        {!collapsed && (
          <div>
            <p className="text-sm font-bold leading-tight">CyberSec AI</p>
            <p className="text-xs text-muted-foreground">Vulnerability Agent</p>
          </div>
        )}
      </div>
      <Separator />
      <nav className="flex-1 space-y-1 px-2 py-2">
        {navItems.map((item) => (
          <NavItem
            key={item.path}
            item={item}
            isActive={isActive(item.path)}
            collapsed={collapsed}
            onClick={onNavClick}
          />
        ))}
      </nav>
      <Separator />
      <div className="px-2 py-2">
        <button
          onClick={() => authService.logout()}
          className={cn(
            'flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground transition-all hover:bg-destructive/10 hover:text-destructive',
            collapsed && 'justify-center px-2'
          )}
          title={collapsed ? 'Logout' : undefined}
        >
          <LogOut className="h-5 w-5 shrink-0" />
          {!collapsed && <span>Logout</span>}
        </button>
      </div>
    </div>
  )
}

export default function AppLayout({ children }) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      {/* Desktop Sidebar */}
      <aside
        className={cn(
          'hidden md:flex flex-col border-r bg-card transition-all duration-300',
          sidebarCollapsed ? 'w-16' : 'w-64'
        )}
      >
        <SidebarContent collapsed={sidebarCollapsed} />
        <button
          onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
          className="absolute left-0 top-1/2 -translate-y-1/2 translate-x-full z-10 hidden md:flex h-6 w-6 items-center justify-center rounded-full border bg-background shadow-md hover:bg-accent transition-colors"
          style={{ marginLeft: sidebarCollapsed ? '64px' : '256px', transition: 'margin-left 0.3s' }}
          title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {sidebarCollapsed ? (
            <ChevronRight className="h-3 w-3" />
          ) : (
            <ChevronLeft className="h-3 w-3" />
          )}
        </button>
      </aside>

      {/* Main area */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Header */}
        <header className="sticky top-0 z-40 flex h-16 items-center gap-4 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 px-4 md:px-6">
          {/* Mobile menu */}
          <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
            <SheetTrigger asChild>
              <Button variant="ghost" size="icon" className="md:hidden">
                <Menu className="h-5 w-5" />
                <span className="sr-only">Toggle menu</span>
              </Button>
            </SheetTrigger>
            <SheetContent side="left" className="w-64 p-0">
              <SidebarContent collapsed={false} onNavClick={() => setMobileOpen(false)} />
            </SheetContent>
          </Sheet>

          {/* Logo (mobile) */}
          <div className="flex items-center gap-2 md:hidden">
            <Shield className="h-5 w-5 text-primary" />
            <span className="font-bold text-sm">CyberSec AI</span>
          </div>

          {/* Spacer */}
          <div className="flex-1" />

          {/* Right actions */}
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="relative h-9 w-9 rounded-full">
                  <Avatar className="h-9 w-9">
                    <AvatarFallback className="bg-primary text-primary-foreground text-xs font-bold">
                      U
                    </AvatarFallback>
                  </Avatar>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent className="w-56" align="end" forceMount>
                <DropdownMenuLabel className="font-normal">
                  <div className="flex flex-col space-y-1">
                    <p className="text-sm font-medium leading-none">Utilisateur</p>
                    <p className="text-xs leading-none text-muted-foreground">cybersec@company.com</p>
                  </div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem>
                  <Settings className="mr-2 h-4 w-4" />
                  Paramètres
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="text-destructive focus:text-destructive"
                  onClick={() => authService.logout()}
                >
                  <LogOut className="mr-2 h-4 w-4" />
                  Déconnexion
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto">
          <div className="container max-w-7xl mx-auto p-6">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}
