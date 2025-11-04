import React, { useState, useRef, useEffect, useMemo } from 'react';
import type { Screen } from '../types';
import { HomeIcon, ChartIcon, BellIcon, UserIcon, SettingsIcon, LogoutIcon, UserPlusIcon, SearchIcon } from '../components/icons';
import { apiService, LeaderboardEntry } from '../src/services/api';
import { websocketService } from '../src/services/websocket';

interface HomeScreenProps {
  onNavigate: (screen: Screen) => void;
  user: any;
}

const leaderboardData = [
  { name: 'John', avatar: 'https://picsum.photos/seed/john/40/40', steps: 5800 },
  { name: 'Sophie', avatar: 'https://picsum.photos/seed/sophie/40/40', steps: 5500 },
  { name: 'Jacob', avatar: 'https://picsum.photos/seed/jacob/40/40', steps: 5100 },
];

const suggestedFriends = [
    { name: 'Olivia', avatar: 'https://picsum.photos/seed/olivia/40/40' },
    { name: 'Liam', avatar: 'https://picsum.photos/seed/liam/40/40' },
    { name: 'Emma', avatar: 'https://picsum.photos/seed/emma/40/40' },
    { name: 'Noah', avatar: 'https://picsum.photos/seed/noah/40/40' },
    { name: 'Ava', avatar: 'https://picsum.photos/seed/ava/40/40' },
];

const LiquidProgress = ({ progress }: { progress: number }) => {
  const uniqueId = "wave-clip-path";
  // The SVG height is 200. Progress will map from 0 to 100.
  // When progress is 0, we want translateY to be 200 (fully hidden at bottom).
  // When progress is 100, we want translateY to be 0 (fully visible at top).
  const yPosition = (100 - progress) * 2; // (100 - progress) / 100 * 200

  return (
    <div className="absolute bottom-0 left-0 w-full h-full">
      <svg width="100%" height="100%" viewBox="0 0 400 200" preserveAspectRatio="none">
        <g style={{ transform: `translateY(${yPosition}px)` }} className="transition-transform duration-1000 ease-in-out">
          {/* Wave 1 - Slower, less opaque */}
          <path
            d="M -400 100 C -300 50, -200 50, -100 100 S 0 150, 100 100 S 200 50, 300 100 S 400 150, 500 100 S 600 50, 700 100 S 800 150, 900 100 V 300 H -400 Z"
            fill="rgba(255, 255, 255, 0.2)"
            className="animate-wave-slow"
          />
          {/* Wave 2 - Faster, more opaque */}
          <path
            d="M -400 110 C -300 60, -200 60, -100 110 S 0 160, 100 110 S 200 60, 300 110 S 400 160, 500 110 S 600 60, 700 110 S 800 160, 900 110 V 300 H -400 Z"
            fill="rgba(255, 255, 255, 0.3)"
            className="animate-wave-fast"
          />
        </g>
      </svg>
    </div>
  );
};


const HomeScreen: React.FC<HomeScreenProps> = ({ onNavigate, user }) => {
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const [friendSearchTerm, setFriendSearchTerm] = useState('');
  const [leaderboardData, setLeaderboardData] = useState<LeaderboardEntry[]>([]);
  const [suggestedFriends, setSuggestedFriends] = useState<any[]>([]);
  const [currentSteps, setCurrentSteps] = useState(0);
  const [goalSteps, setGoalSteps] = useState(user?.dailyStepGoal || 6000);
  const [isLoading, setIsLoading] = useState(true);

  // Initialize and update goalSteps when user prop changes
  useEffect(() => {
    console.log('=== HOMESCREEN USER EFFECT ===');
    console.log('Current user:', user);
    
    if (user?.dailyStepGoal !== undefined) {
      console.log('User prop updated - dailyStepGoal:', user.dailyStepGoal, 'Current goalSteps:', goalSteps);
      
      // Always update goalSteps from user prop to ensure it's in sync
      setGoalSteps(user.dailyStepGoal);
      
      // Also update current steps if needed
      const loadSteps = async () => {
        if (user.id) {
          try {
            console.log('Loading user runs to calculate current steps...');
            const userRuns = await apiService.getUserRuns(user.id);
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            const todayRuns = userRuns.filter(run => {
              if (!run.startTime) return false;
              const runDate = new Date(run.startTime);
              runDate.setHours(0, 0, 0, 0);
              return runDate.getTime() === today.getTime();
            });
            const totalStepsToday = todayRuns.reduce((sum, run) => sum + (run.totalSteps || 0), 0);
            console.log('Total steps today:', totalStepsToday);
            setCurrentSteps(totalStepsToday);
          } catch (error) {
            console.error('Error loading user runs:', error);
          }
        }
      };
      
      loadSteps();
    } else {
      console.log('No dailyStepGoal in user object, using default 6000');
      setGoalSteps(6000);
    }
  }, [user, user?.id, user?.dailyStepGoal]);

  const progress = Math.min((currentSteps / goalSteps) * 100, 100);

  const filteredFriends = useMemo(() => {
    return suggestedFriends.filter(friend =>
      friend.name.toLowerCase().includes(friendSearchTerm.toLowerCase())
    );
  }, [friendSearchTerm]);

  useEffect(() => {
    const loadData = async () => {
      try {
        // Load leaderboard data
        const leaderboard = await apiService.getDailyLeaderboard();
        setLeaderboardData(leaderboard);
        
        // Load suggested friends (exclude current user if available)
        const friends = await apiService.searchUsers('');
        const filtered = user ? friends.filter((u: any) => u.id !== user.id) : friends;
        setSuggestedFriends(filtered.slice(0, 5));
        
        // Load user's current steps (mock data for now)
        setCurrentSteps(5000);
        
        setIsLoading(false);
      } catch (error) {
        console.error('Error loading data:', error);
        setIsLoading(false);
      }
    };

    loadData();
  }, []);

  // Initialize static campus map with mock territories
  useEffect(() => {
    const container = document.getElementById('home-map');
    if (!container) return;
    // guard against re-init
    if ((container as any)._leaflet_id) return;

    // SRM KTR approximate center
    const SRM_CENTER: [number, number] = [12.8232, 80.0452];
    const SRM_BOUNDS = (window as any).L.latLngBounds([12.8195, 80.0400], [12.8275, 80.0490]);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const map: any = (window as any).L?.map(container, { maxBounds: SRM_BOUNDS, maxBoundsViscosity: 1.0 }).setView(SRM_CENTER, 16);
    if (!map) return;
    (window as any).L.tileLayer('https://{s}.google.com/vt/lyrs=m&x={x}&y={y}&z={z}', {
      maxZoom: 20,
      subdomains:['mt0','mt1','mt2','mt3'],
      attribution: '&copy; Google Maps'
    }).addTo(map);

    // Mock territories (lat,lon pairs)
    const mockPolygons: [number, number][][] = [
      [ [12.8238,80.0409],[12.8246,80.0421],[12.8242,80.0434],[12.8233,80.0422] ],
      [ [12.8219,80.0455],[12.8227,80.0465],[12.8222,80.0476],[12.8213,80.0465] ],
      [ [12.8249,80.0462],[12.8256,80.0471],[12.8251,80.0479],[12.8243,80.0469] ]
    ];
    mockPolygons.forEach((ring) => {
      (window as any).L.polygon(ring, { color: '#22c55e', fillColor: '#22c55e', fillOpacity: 0.25 }).addTo(map);
    });
  }, []);

  useEffect(() => {
    // Connect to WebSocket for real-time updates
    websocketService.connect().then(() => {
      websocketService.subscribeToDailyLeaderboard((data) => {
        setLeaderboardData(data);
      });
      websocketService.requestDailyLeaderboard();
    });

    return () => {
      websocketService.disconnect();
    };
  }, []);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsDropdownOpen(false);
      }
    };

    if (isDropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isDropdownOpen]);

  const getRankClass = (index: number) => {
    switch (index) {
      case 0: return 'text-yellow-400';
      case 1: return 'text-gray-300';
      case 2: return 'text-orange-400';
      default: return 'text-gray-500';
    }
  };

  const getMedalSymbol = (index: number) => {
    switch (index) {
      case 0: return '🥇';
      case 1: return '🥈';
      case 2: return '🥉';
      default: return null;
    }
  };

  return (
    <div className="flex flex-col h-full text-white bg-[#0F172A]">
        <style>{`
          @keyframes wave-slow {
            0% { transform: translateX(0); }
            100% { transform: translateX(-400px); }
          }
          .animate-wave-slow {
            animation: wave-slow 10s linear infinite;
          }

          @keyframes wave-fast {
            0% { transform: translateX(0); }
            100% { transform: translateX(-400px); }
          }
          .animate-wave-fast {
            animation: wave-fast 6s linear infinite;
          }
        `}</style>
      <header className="flex justify-between items-center p-6 pt-12">
        <div>
          <h1 className="text-2xl font-bold">Home</h1>
        </div>
        <div className="flex items-center space-x-4">
          <span className="text-lg font-semibold">Athlos</span>
          <div className="relative">
            <img 
              src={user?.avatar || `https://i.pravatar.cc/40?u=${user?.id}`} 
              alt="User Avatar" 
              className="w-10 h-10 rounded-full cursor-pointer"
              onClick={() => setIsDropdownOpen(!isDropdownOpen)}
            />
            {isDropdownOpen && (
              <div ref={dropdownRef} className="absolute right-0 mt-2 w-48 bg-slate-800 rounded-lg shadow-lg py-2 z-20 origin-top-right animate-in fade-in-20 slide-in-from-top-2">
                <button
                  onClick={() => {
                    setIsDropdownOpen(false);
                    onNavigate('profile');
                  }}
                  className="w-full flex items-center text-left px-4 py-2 text-sm text-gray-300 hover:bg-red-600 hover:text-white rounded-t-lg"
                >
                  <UserIcon className="w-5 h-5 mr-3" />
                  Profile
                </button>
                <button
                  onClick={() => {
                    setIsDropdownOpen(false);
                    onNavigate('settings');
                  }}
                  className="w-full flex items-center text-left px-4 py-2 text-sm text-gray-300 hover:bg-red-600 hover:text-white"
                >
                  <SettingsIcon className="w-5 h-5 mr-3" />
                  Settings
                </button>
                <div className="border-t border-gray-700 my-1"></div>
                <button
                  onClick={() => {
                    setIsDropdownOpen(false);
                    onNavigate('signin');
                  }}
                  className="w-full flex items-center text-left px-4 py-2 text-sm text-red-400 hover:bg-red-500 hover:text-white rounded-b-lg"
                >
                  <LogoutIcon className="w-5 h-5 mr-3" />
                  Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className="flex-grow p-6 overflow-y-auto">
        <section className="mb-8">
          <div className="bg-gradient-to-br from-red-500 to-orange-500 p-6 rounded-2xl shadow-lg relative overflow-hidden h-[150px] flex flex-col justify-center">
            <LiquidProgress progress={progress} />
            <div className="relative z-10">
                <h3 className="text-lg font-semibold text-red-200">Steps</h3>
                <p className="text-4xl font-bold my-1">{currentSteps.toLocaleString()} / <span className="text-2xl font-normal text-red-200">{goalSteps.toLocaleString()}</span></p>
                <p className="text-sm text-red-200">You have covered {Math.round(progress)}% of the goal</p>
            </div>
          </div>
        </section>

        <section className="mb-8">
          <h2 className="text-xl font-bold mb-4">Leaderboard</h2>
          <div className="bg-slate-800 p-4 rounded-2xl">
            {isLoading ? (
              <div className="text-center py-4">
                <p className="text-gray-400">Loading leaderboard...</p>
              </div>
            ) : (
              <ul className="space-y-4">
                {leaderboardData.slice(0, 3).map((entry, index) => (
                  <li key={entry.userId} className="flex items-center justify-between">
                    <div className="flex items-center">
                      <span className={`w-8 text-center text-xl font-bold ${getRankClass(index)}`}>{entry.rank}</span>
                      <img src={entry.avatar} alt={entry.name} className="w-10 h-10 rounded-full mx-4" />
                      <span className="text-xl mr-2">{getMedalSymbol(index)}</span>
                      <span className="font-semibold">{entry.name}</span>
                    </div>
                    <span className="text-gray-400">{entry.totalSteps.toLocaleString()} steps</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>

        <section className="mt-8">
          <h2 className="text-xl font-bold mb-4">Campus Map</h2>
          <div className="bg-slate-800 p-0 rounded-2xl overflow-hidden">
            <div id="home-map" className="w-full h-[300px]"></div>
          </div>
        </section>

        <button 
          onClick={() => onNavigate('disclaimer')}
          className="w-full py-5 bg-red-600 rounded-2xl font-bold text-lg hover:bg-red-700 transition-colors shadow-lg"
        >
          Start RUN
        </button>

        <section className="mt-8">
            <h2 className="text-xl font-bold mb-4">Connect with Friends</h2>
            <div className="bg-slate-800 p-4 rounded-2xl">
                <div className="relative mb-4">
                    <input
                        type="text"
                        placeholder="Search for friends..."
                        value={friendSearchTerm}
                        onChange={(e) => setFriendSearchTerm(e.target.value)}
                        className="w-full p-3 pl-10 bg-slate-900 rounded-lg border border-transparent focus:border-red-500 focus:outline-none focus:ring-1 focus:ring-red-500 transition"
                    />
                    <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                </div>
                {filteredFriends.length > 0 ? (
                    <ul className="space-y-4">
                        {filteredFriends.map((friend, index) => (
                            <li key={index} className="flex items-center justify-between">
                                <div className="flex items-center">
                                    <img src={friend.avatar} alt={friend.name} className="w-10 h-10 rounded-full" />
                                    <span className="font-semibold ml-4">{friend.name}</span>
                                </div>
                                <button className="flex items-center px-4 py-2 bg-red-600/20 text-red-400 rounded-full hover:bg-red-600/40 transition">
                                    <UserPlusIcon className="w-5 h-5 mr-2" />
                                    Add
                                </button>
                            </li>
                        ))}
                    </ul>
                ) : (
                    <div className="text-center py-4">
                        <p className="text-gray-400">No users found.</p>
                    </div>
                )}
            </div>
        </section>

      </main>
      
      <footer className="w-full bg-slate-800 p-4 rounded-t-3xl">
        <nav className="flex justify-around items-center">
          <button className="p-2 text-red-400">
            <HomeIcon className="w-8 h-8" />
          </button>
          <button onClick={() => onNavigate('leaderboard')} className="p-2 text-gray-500 hover:text-red-400 transition-colors">
            <ChartIcon className="w-8 h-8" />
          </button>
          <button className="p-2 text-gray-500 hover:text-red-400 transition-colors">
            <BellIcon className="w-8 h-8" />
          </button>
        </nav>
      </footer>
    </div>
  );
};

export default HomeScreen;
