// Hardcoded API base URL to ensure it always points to the correct backend
const API_BASE_URL = 'http://localhost:8081/api';

// Log the API base URL for debugging
console.log('API Base URL:', API_BASE_URL);

export interface User {
  id: number;
  email: string;
  name: string;
  age?: number;
  gender?: string;
  dailyStepGoal: number;
  latitude?: number;
  longitude?: number;
  createdAt: string;
  lastActive: string;
}

export interface Run {
  id: number;
  userId: number;
  startTime: string;
  endTime?: string;
  durationSeconds?: number;
  totalSteps?: number;
  distanceMeters?: number;
  path?: Point[];
  claimedTerritory?: Point[];
  isActive: boolean;
}

export interface Point {
  latitude: number;
  longitude: number;
}

export interface LeaderboardEntry {
  userId: number;
  name: string;
  avatar: string;
  totalSteps: number;
  rank: number;
  totalDistance?: number;
  territoriesClaimed?: number;
}

class ApiService {
  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${API_BASE_URL}${endpoint}`;
    const config: RequestInit = {
      headers: {
        'Content-Type': 'application/json',
        ...(localStorage.getItem('athlos_token') ? { 'Authorization': `Bearer ${localStorage.getItem('athlos_token')}` } : {}),
        ...options.headers,
      },
      credentials: 'include' as RequestCredentials, // Include credentials for CORS
      ...options,
    };

    try {
      const response = await fetch(url, config);
      
      if (!response.ok) {
        let errorMessage = `API Error: ${response.status} ${response.statusText}`;
        
        // Try to parse error message from response
        try {
          const errorData = await response.json();
          if (errorData.message) {
            errorMessage = errorData.message;
          } else if (errorData.error) {
            errorMessage = errorData.error;
          }
        } catch (e) {
          // If we can't parse JSON, use the default error message
        }
        
        throw new Error(errorMessage);
      }

      return response.json();
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error('Network error occurred');
    }
  }

  // User endpoints
  async register(email: string, password: string, name: string): Promise<User> {
    return this.request<User>('/users/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, name }),
    });
  }

  async login(email: string, password: string): Promise<User> {
    const res = await this.request<{ user: User; token: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    localStorage.setItem('athlos_token', res.token);
    // Ensure user has a default dailyStepGoal
    const userWithGoal = {
      ...res.user,
      dailyStepGoal: res.user.dailyStepGoal || 0, // Default to 0 if not set
    };
    localStorage.setItem('athlos_user', JSON.stringify(userWithGoal));
    return userWithGoal;
  }

  logout(): void {
    localStorage.removeItem('athlos_token');
    localStorage.removeItem('athlos_user');
    localStorage.removeItem('athlos_is_guest');
  }

  isAuthenticated(): boolean {
    return !!localStorage.getItem('athlos_token');
  }

  async getUser(id: number): Promise<User> {
    return this.request<User>(`/users/${id}`);
  }

  async updateUser(id: number, userData: Partial<User>): Promise<User> {
    const updatedUser = await this.request<User>(`/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(userData),
    });
    
    // Update the user in localStorage if it's the current user
    const currentUser = JSON.parse(localStorage.getItem('athlos_user') || 'null');
    if (currentUser && currentUser.id === id) {
      const mergedUser = { ...currentUser, ...userData, ...updatedUser };
      localStorage.setItem('athlos_user', JSON.stringify(mergedUser));
      return mergedUser;
    }
    
    return updatedUser;
  }

  async updateLocation(id: number, latitude: number, longitude: number): Promise<void> {
    return this.request<void>(`/users/${id}/location`, {
      method: 'PUT',
      body: JSON.stringify({ latitude, longitude }),
    });
  }

  async searchUsers(query: string): Promise<User[]> {
    return this.request<User[]>(`/users/search?q=${encodeURIComponent(query)}`);
  }

  // Run endpoints
  async startRun(userId: number): Promise<Run> {
    return this.request<Run>('/runs/start', {
      method: 'POST',
      body: JSON.stringify({ userId }),
    });
  }

  async pauseRun(runId: number): Promise<Run> {
    return this.request<Run>(`/runs/${runId}/pause`, {
      method: 'POST',
    });
  }

  async resumeRun(runId: number): Promise<Run> {
    return this.request<Run>(`/runs/${runId}/resume`, {
      method: 'POST',
    });
  }

  async endRun(runId: number): Promise<Run> {
    return this.request<Run>(`/runs/${runId}/end`, {
      method: 'POST',
    });
  }

  async addRunPoint(runId: number, latitude: number, longitude: number, stepCount?: number): Promise<Run> {
    return this.request<Run>(`/runs/${runId}/point`, {
      method: 'POST',
      body: JSON.stringify({ latitude, longitude, stepCount }),
    });
  }

  async getUserRuns(userId: number): Promise<Run[]> {
    return this.request<Run[]>(`/runs/user/${userId}`);
  }

  async getActiveRun(userId: number): Promise<Run | null> {
    try {
      return await this.request<Run>(`/runs/user/${userId}/active`);
    } catch (error) {
      return null;
    }
  }

  // Leaderboard endpoints
  async getDailyLeaderboard(): Promise<LeaderboardEntry[]> {
    return this.request<LeaderboardEntry[]>('/leaderboard/daily');
  }

  async getWeeklyLeaderboard(): Promise<LeaderboardEntry[]> {
    return this.request<LeaderboardEntry[]>('/leaderboard/weekly');
  }

  async getAllTimeLeaderboard(): Promise<LeaderboardEntry[]> {
    return this.request<LeaderboardEntry[]>('/leaderboard/all-time');
  }
}

export const apiService = new ApiService();

