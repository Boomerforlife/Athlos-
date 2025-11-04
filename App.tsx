import React, { useState, useEffect } from 'react';
import type { Screen } from './types';
import WelcomeScreen from './screens/WelcomeScreen';
import SignUpScreen from './screens/SignUpScreen';
import SignInScreen from './screens/SignInScreen';
import PersonalInfoScreen from './screens/PersonalInfoScreen';
import GoalSettingScreen from './screens/GoalSettingScreen';
import HomeScreen from './screens/HomeScreen';
import ProfileScreen from './screens/ProfileScreen';
import SettingsScreen from './screens/SettingsScreen';
import EditProfileScreen from './screens/EditProfileScreen';
import LeaderboardScreen from './screens/LeaderboardScreen';
import DisclaimerScreen from './screens/DisclaimerScreen';
import RunScreen from './screens/RunScreen';
import { User, apiService } from './src/services/api';

const App: React.FC = () => {
  const [screen, setScreen] = useState<Screen>('welcome');
  const [user, setUser] = useState<User | null>(null);

  const navigate = (newScreen: Screen): void => {
    setScreen(newScreen);
  };

  const handleUserLogin = (userData: User) => {
    console.log('User logged in:', userData);
    setUser(userData);
<<<<<<< Updated upstream
    setScreen('home');
=======
    
    // Always redirect to goals page after signup to ensure goal is set
    console.log('Redirecting to goals page');
    setScreen('goalsetting');
    
    // The following code is kept for reference but commented out
    /*
    // Check if user has set a daily step goal
    if (!userData.dailyStepGoal || userData.dailyStepGoal === 0) {
      console.log('No goal set, redirecting to goals page');
      setScreen('goalsetting');
    } else {
      console.log('Goal already set, redirecting to home');
      setScreen('home');
    }
    */
>>>>>>> Stashed changes
  };

  const handleUserLogout = () => {
    apiService.logout();
    setUser(null);
    setScreen('welcome');
  };

<<<<<<< Updated upstream
  const handleGuestLogin = () => {
    const guestUser: User = {
      id: 0,
      email: 'guest@example.com',
      name: 'Guest',
      dailyStepGoal: 6000,
      createdAt: new Date().toISOString(),
      lastActive: new Date().toISOString(),
    } as any;
    localStorage.setItem('athlos_is_guest', 'true');
    setUser(guestUser);
    setScreen('home');
=======
  const handleUserUpdate = (updatedUser: User) => {
    console.log('=== UPDATING USER DATA ===');
    console.log('Previous user data:', user);
    console.log('New user data:', updatedUser);
    
    // Ensure we have the latest data by merging with existing user data
    const mergedUser = { ...user, ...updatedUser };
    
    // Update the state
    setUser(mergedUser);
    
    // Update localStorage
    localStorage.setItem('athlos_user', JSON.stringify(mergedUser));
    console.log('User data updated in state and localStorage');
    
    // Force a re-render of the home screen by toggling the screen
    setScreen('home');
    setTimeout(() => setScreen('home'), 100);
>>>>>>> Stashed changes
  };

  // Check for existing user session on app load
  useEffect(() => {
    const savedUser = localStorage.getItem('athlos_user');
    const hasToken = !!localStorage.getItem('athlos_token');
    if (savedUser) {
      try {
        const userData = JSON.parse(savedUser);
        // Prefer real auth sessions over guest
        if (hasToken || localStorage.getItem('athlos_is_guest') === 'true') {
          setUser(userData);
          setScreen('home');
        }
      } catch (error) {
        console.error('Error parsing saved user data:', error);
        localStorage.removeItem('athlos_user');
      }
    }
  }, []);

  // Save user to localStorage when user changes
  useEffect(() => {
    if (user) {
      localStorage.setItem('athlos_user', JSON.stringify(user));
    } else {
      localStorage.removeItem('athlos_user');
    }
  }, [user]);

  const renderScreen = () => {
    switch (screen) {
      case 'welcome':
        return <WelcomeScreen onNavigate={navigate} />;
      case 'signup':
        return <SignUpScreen onNavigate={navigate} onUserLogin={handleUserLogin} onGuestLogin={handleGuestLogin} />;
      case 'signin':
        return <SignInScreen onNavigate={navigate} onUserLogin={handleUserLogin} onGuestLogin={handleGuestLogin} />;
      case 'personalinfo':
        return <PersonalInfoScreen onNavigate={navigate} user={user} />;
      case 'goalsetting':
        return <GoalSettingScreen onNavigate={navigate} user={user} />;
      case 'home':
        return <HomeScreen onNavigate={navigate} user={user} />;
      case 'profile':
        return <ProfileScreen onNavigate={navigate} user={user} />;
      case 'settings':
        return <SettingsScreen onNavigate={navigate} user={user} />;
      case 'editprofile':
        return <EditProfileScreen onNavigate={navigate} user={user} />;
      case 'leaderboard':
        return <LeaderboardScreen onNavigate={navigate} user={user} />;
      case 'disclaimer':
        return <DisclaimerScreen onNavigate={navigate} user={user} />;
      case 'run':
        return <RunScreen onNavigate={navigate} user={user} />;
      default:
        return <WelcomeScreen onNavigate={navigate} />;
    }
  };

  return (
    <div className="min-h-screen bg-black flex items-center justify-center font-sans antialiased text-white">
      <div className="relative w-full max-w-[400px] h-[844px] bg-[#0F172A] overflow-hidden shadow-2xl rounded-3xl">
        <div className="absolute top-0 left-0 w-full px-8 py-3 flex justify-between items-center z-50">
            <div className="flex items-center space-x-1">
              <span className="font-semibold text-sm">9:41</span>
            </div>
            <div className="w-24 h-8 bg-black/80 backdrop-blur-sm rounded-full"></div>
            <div className="flex items-center space-x-2">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M18.364 5.636a9 9 0 010 12.728M12 18.001v.01"></path><path d="M8.5 12.5a3.5 3.5 0 013.5-3.5h0a3.5 3.5 0 013.5 3.5v0a3.5 3.5 0 01-3.5 3.5h0a3.5 3.5 0 01-3.5-3.5z"></path></svg>
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path d="M18 9.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0zM11.5 9.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0zM5 9.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0z"></path></svg>
                <div className="w-6 h-3 border-2 border-white rounded-sm flex items-center p-0.5"><div className="w-3/4 h-full bg-white rounded-xs"></div></div>
            </div>
        </div>
        <div className="h-full w-full">
            {renderScreen()}
        </div>
      </div>
    </div>
  );
};

export default App;
