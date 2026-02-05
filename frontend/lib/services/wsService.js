/**
 * Service WebSocket pour la progression en temps réel des scans
 */
export class WebSocketService {
  constructor(scanId, onProgress, onError, onClose) {
    const wsUrl = process.env.REACT_APP_WS_URL || 'ws://localhost:8000';
    const wsPath = `/ws/scan/${scanId}`;
    const fullUrl = `${wsUrl}${wsPath}`;
    
    this.ws = new WebSocket(fullUrl);
    this.scanId = scanId;
    this.onProgress = onProgress;
    this.onError = onError;
    this.onClose = onClose;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 3000; // 3 secondes
    
    this.setupEventHandlers();
  }
  
  setupEventHandlers() {
    this.ws.onopen = () => {
      console.log(`WebSocket connecté pour scan ${this.scanId}`);
      this.reconnectAttempts = 0;
      
      // Envoyer un ping initial
      this.send('ping');
    };
    
    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        // Gérer les différents types de messages
        if (data.type === 'progress_update') {
          this.onProgress(data.data);
        } else if (data === 'pong') {
          // Réponse au ping, ne rien faire
          return;
        } else {
          // Message générique
          this.onProgress(data);
        }
      } catch (error) {
        console.error('Erreur parsing message WebSocket:', error);
      }
    };
    
    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      if (this.onError) {
        this.onError(error);
      }
    };
    
    this.ws.onclose = (event) => {
      console.log(`WebSocket fermé pour scan ${this.scanId}`, event.code, event.reason);
      
      // Tentative de reconnexion si la fermeture n'était pas intentionnelle
      if (event.code !== 1000 && this.reconnectAttempts < this.maxReconnectAttempts) {
        this.reconnect();
      } else if (this.onClose) {
        this.onClose(event);
      }
    };
  }
  
  send(message) {
    if (this.ws.readyState === WebSocket.OPEN) {
      if (typeof message === 'string') {
        this.ws.send(message);
      } else {
        this.ws.send(JSON.stringify(message));
      }
    } else {
      console.warn('WebSocket n\'est pas ouvert, message non envoyé:', message);
    }
  }
  
  reconnect() {
    this.reconnectAttempts++;
    console.log(`Tentative de reconnexion ${this.reconnectAttempts}/${this.maxReconnectAttempts}...`);
    
    setTimeout(() => {
      const wsUrl = process.env.REACT_APP_WS_URL || 'ws://localhost:8000';
      const wsPath = `/ws/scan/${this.scanId}`;
      const fullUrl = `${wsUrl}${wsPath}`;
      
      this.ws = new WebSocket(fullUrl);
      this.setupEventHandlers();
    }, this.reconnectDelay);
  }
  
  close() {
    this.reconnectAttempts = this.maxReconnectAttempts; // Empêcher la reconnexion
    if (this.ws) {
      this.ws.close(1000, 'Fermeture intentionnelle');
    }
  }
}

export default WebSocketService;
