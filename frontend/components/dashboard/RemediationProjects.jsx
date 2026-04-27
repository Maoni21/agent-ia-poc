import { useState } from 'react';
import { Card, CardHeader, CardContent, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { Progress } from '@/components/ui/progress';
import { AlertTriangle, Clock, CheckCircle, Plus } from 'lucide-react';

const PRIORITY_COLORS = {
  critical: 'bg-red-500 text-white',
  high:     'bg-orange-500 text-white',
  medium:   'bg-yellow-500 text-black',
  low:      'bg-green-500 text-white',
};

const STATUS_ICONS = {
  open:        <Clock className="h-4 w-4 text-gray-400" />,
  in_progress: <AlertTriangle className="h-4 w-4 text-orange-400" />,
  completed:   <CheckCircle className="h-4 w-4 text-green-500" />,
  cancelled:   <CheckCircle className="h-4 w-4 text-gray-400" />,
};

function ProjectRow({ project }) {
  const priorityClass = PRIORITY_COLORS[project.priority] || 'bg-gray-400 text-white';
  const isOverdue = project.days_remaining !== null && project.days_remaining < 0;
  const isUrgent  = project.days_remaining !== null && project.days_remaining >= 0 && project.days_remaining <= 7;

  return (
    <div className="p-4 border-b last:border-0 hover:bg-muted/30 transition-colors">
      <div className="flex items-start justify-between gap-4">
        {/* Nom + statut */}
        <div className="flex items-center gap-2 min-w-0">
          {STATUS_ICONS[project.status]}
          <span className="font-medium truncate">{project.name}</span>
        </div>

        {/* Priority badge */}
        <Badge className={`shrink-0 text-xs ${priorityClass}`}>
          {project.priority.toUpperCase()}
        </Badge>
      </div>

      {/* Progress bar */}
      <div className="mt-3 space-y-1">
        <div className="flex justify-between text-xs text-muted-foreground">
          <span>{project.resolved_vulns}/{project.total_vulns} vulns résolues</span>
          <span>{project.progress}%</span>
        </div>
        <Progress value={project.progress} className="h-2" />
      </div>

      {/* Due date */}
      {project.due_date && (
        <div className={`mt-2 text-xs flex items-center gap-1 ${
          isOverdue ? 'text-red-500 font-semibold' :
          isUrgent  ? 'text-orange-500 font-semibold' :
          'text-muted-foreground'
        }`}>
          <Clock className="h-3 w-3" />
          {isOverdue
            ? `En retard de ${Math.abs(project.days_remaining)} jours`
            : isUrgent
            ? `J-${project.days_remaining}`
            : `Échéance dans ${project.days_remaining} jours`
          }
        </div>
      )}
    </div>
  );
}

export function RemediationProjects({ projects, loading, onCreateProject }) {
  if (loading) {
    return (
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-base">Projets de remédiation</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="space-y-2">
              <Skeleton className="h-5 w-3/4" />
              <Skeleton className="h-2 w-full" />
            </div>
          ))}
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-base">Projets de remédiation</CardTitle>
        {onCreateProject && (
          <Button size="sm" variant="outline" onClick={onCreateProject}>
            <Plus className="h-4 w-4 mr-1" />
            Nouveau
          </Button>
        )}
      </CardHeader>
      <CardContent className="p-0">
        {!projects || projects.length === 0 ? (
          <div className="p-6 text-center text-sm text-muted-foreground">
            <CheckCircle className="h-8 w-8 text-green-500 mx-auto mb-2" />
            Aucun projet en cours
          </div>
        ) : (
          <div>
            {projects.map((p) => (
              <ProjectRow key={p.id} project={p} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
