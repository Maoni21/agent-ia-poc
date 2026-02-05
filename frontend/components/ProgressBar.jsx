import React from 'react';
import {
  Box,
  LinearProgress,
  Typography,
  Paper,
} from '@mui/material';

const ProgressBar = ({ progress, currentStep, message, estimatedTime }) => {
  const formatTime = (seconds) => {
    if (!seconds || seconds <= 0) return '0s';
    
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    
    if (minutes > 0) {
      return `${minutes}m ${secs}s`;
    }
    return `${secs}s`;
  };

  return (
    <Paper elevation={2} sx={{ p: 2, mb: 2 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
        <Typography variant="body1" fontWeight="bold">
          {currentStep || 'En cours...'}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {progress !== undefined ? `${progress}%` : '0%'}
        </Typography>
      </Box>
      
      <LinearProgress
        variant="determinate"
        value={progress || 0}
        sx={{ height: 8, borderRadius: 4, mb: 1 }}
      />
      
      <Box display="flex" justifyContent="space-between" alignItems="center">
        <Typography variant="body2" color="text.secondary">
          {message || 'Traitement en cours...'}
        </Typography>
        {estimatedTime !== undefined && estimatedTime > 0 && (
          <Typography variant="body2" color="text.secondary">
            Temps restant: ~{formatTime(estimatedTime)}
          </Typography>
        )}
      </Box>
    </Paper>
  );
};

export default ProgressBar;
