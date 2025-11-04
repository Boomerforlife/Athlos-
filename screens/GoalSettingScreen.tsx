import React, { useState, useMemo, useRef, useEffect } from 'react';
import type { Screen } from '../types';
import { MinusIcon, PlusIcon } from '../components/icons';

// Fix: Updated props to accept an optional `onNext` callback to handle navigation within the onboarding flow. `onNavigate` is also made optional.
interface GoalSettingScreenProps {
  onNavigate?: (screen: Screen) => void;
  onNext?: () => void;
}

const GoalSettingScreen: React.FC<GoalSettingScreenProps> = ({ onNavigate, onNext }) => {
  const [goal, setGoal] = useState(6000);
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const scrollTimeoutRef = useRef<number | null>(null);

  const goals = useMemo(() => Array.from({ length: 191 }, (_, i) => 1000 + i * 100), []);
  const ITEM_HEIGHT = 48; // Corresponds to h-12 in Tailwind
  const CONTAINER_HEIGHT = 240; // Corresponds to h-60

  // Effect to synchronize scroll position with the current goal state
  useEffect(() => {
    if (scrollContainerRef.current) {
      const targetIndex = goals.findIndex(g => g === goal);
      const targetScrollTop = targetIndex * ITEM_HEIGHT;
      // Only scroll if it's not already at the target to prevent loops
      if (scrollContainerRef.current.scrollTop !== targetScrollTop) {
        scrollContainerRef.current.scrollTo({
          top: targetScrollTop,
          behavior: 'smooth',
        });
      }
    }
  }, [goal, goals]);

  // Initial scroll setup
  useEffect(() => {
    if (scrollContainerRef.current) {
      const initialIndex = goals.findIndex(g => g === 6000);
      if (initialIndex !== -1) {
        scrollContainerRef.current.scrollTop = initialIndex * ITEM_HEIGHT;
      }
    }
  }, [goals]);

  const handleSaveGoal = async () => {
    if (!user?.id) {
      console.error('No user ID found');
      onNavigate('home');
      return;
    }
    
    console.log('=== SAVING GOAL ===');
    console.log('Current user ID:', user.id);
    console.log('New goal value:', goal);
    
    setIsLoading(true);
    try {
      // First update the user with the new goal
      console.log('Updating user with new goal...');
      const updatedUser = await apiService.updateUser(user.id, {
        ...user,  // Include all existing user data
        dailyStepGoal: goal
      });
      
      console.log('User updated successfully:', updatedUser);
      
      // Update the user context and local storage
      if (onUserUpdate) {
        console.log('Calling onUserUpdate with:', updatedUser);
        onUserUpdate(updatedUser);
      } else {
        console.warn('onUserUpdate is not defined');
      }
      
      // Force a small delay to ensure state updates are processed
      setTimeout(() => {
        console.log('Navigating to home screen...');
        onNavigate('home');
      }, 200);
      
    } catch (error) {
      console.error('Error saving goal:', error);
      // Still navigate to home even if there's an error
      onNavigate('home');
    } finally {
      setIsLoading(false);
    }
  };

  const handleScroll = () => {
    if (scrollContainerRef.current) {
      if (scrollTimeoutRef.current) {
        clearTimeout(scrollTimeoutRef.current);
      }
      scrollTimeoutRef.current = window.setTimeout(() => {
        if (scrollContainerRef.current) {
          const scrollTop = scrollContainerRef.current.scrollTop;
          const newIndex = Math.round(scrollTop / ITEM_HEIGHT);
          const newGoal = goals[newIndex];
          if (newGoal && newGoal !== goal) {
            setGoal(newGoal); // This triggers the useEffect to perform the snap
          }
        }
      }, 100); // Wait for scroll to stop
    }
  };

  const changeGoal = (direction: 'inc' | 'dec') => {
    const currentIndex = goals.findIndex(g => g === goal);
    if (direction === 'inc') {
      const nextIndex = Math.min(currentIndex + 1, goals.length - 1);
      setGoal(goals[nextIndex]);
    } else {
      const prevIndex = Math.max(currentIndex - 1, 0);
      setGoal(goals[prevIndex]);
    }
  };
  
  // A helper class to hide scrollbars, as Tailwind CDN might not have the plugin
  const scrollbarHideStyle = {
    '-ms-overflow-style': 'none', /* IE and Edge */
    'scrollbar-width': 'none', /* Firefox */
  };

  return (
    <div className="relative h-full text-white overflow-hidden">
      <div className="absolute inset-0 z-0">
        <img 
          src="https://images.unsplash.com/photo-1744706908605-ac30eb45f98c?q=80&w=2150&auto=format&fit=crop&ixlib=rb-4.1.0&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D"
          alt="A runner on a road at dusk."
          className="w-full h-full object-cover"
        />
        <div className="absolute inset-0 bg-black/60"></div>
        <div className="absolute inset-0 bg-gradient-to-t from-[#0F172A] via-[#0F172A]/80 to-transparent"></div>
      </div>
      <div className="relative z-10 flex flex-col h-full">
        <style>{`.scrollbar-hide::-webkit-scrollbar { display: none; }`}</style>
        <header className="text-center pt-16 px-8">
          <h2 className="text-3xl font-bold">Your Daily Goal</h2>
        </header>

        <main className="flex-grow flex flex-col justify-center items-center text-center px-2">
          <div className="flex items-center justify-center space-x-4">
            <button
              onClick={() => changeGoal('dec')}
              className="p-3 bg-slate-800/80 rounded-full hover:bg-slate-700/80 transition disabled:opacity-50"
              disabled={goal === goals[0]}
            >
              <MinusIcon className="w-6 h-6" />
            </button>

            <div
              ref={scrollContainerRef}
              onScroll={handleScroll}
              className="w-32 overflow-y-scroll snap-y snap-mandatory scrollbar-hide"
              style={{
                ...scrollbarHideStyle,
                height: `${CONTAINER_HEIGHT}px`,
                maskImage: 'linear-gradient(to bottom, transparent, black 25%, black 75%, transparent)',
                WebkitMaskImage: 'linear-gradient(to bottom, transparent, black 25%, black 75%, transparent)',
              }}
            >
              <div style={{ height: `${CONTAINER_HEIGHT / 2 - ITEM_HEIGHT / 2}px` }} />
              <div className="flex flex-col items-center">
                {goals.map((g) => (
                  <div
                    key={g}
                    className="flex items-center justify-center snap-center transition-all duration-300"
                    style={{ minHeight: `${ITEM_HEIGHT}px` }}
                  >
                    <span
                      className={`tabular-nums ${
                        g === goal
                          ? 'text-4xl font-bold text-white'
                          : 'text-2xl font-medium text-gray-500'
                      }`}
                    >
                      {g}
                    </span>
                  </div>
                ))}
              </div>
              <div style={{ height: `${CONTAINER_HEIGHT / 2 - ITEM_HEIGHT / 2}px` }} />
            </div>

            <button
              onClick={() => changeGoal('inc')}
              className="p-3 bg-slate-800/80 rounded-full hover:bg-slate-700/80 transition disabled:opacity-50"
              disabled={goal === goals[goals.length - 1]}
            >
              <PlusIcon className="w-6 h-6" />
            </button>
          </div>
        </main>

        <footer className="px-8 pb-8 pt-4">
          <button
            type="button"
<<<<<<< Updated upstream
            onClick={() => {
              if (onNext) {
                onNext();
              } else if (onNavigate) {
                onNavigate('home');
              }
            }}
            className="w-full max-w-xs mx-auto block py-4 bg-red-600 rounded-lg font-semibold text-lg hover:bg-red-700 transition-colors"
=======
            onClick={handleSaveGoal}
            disabled={isLoading}
            className="w-full max-w-xs mx-auto block py-4 bg-red-600 rounded-lg font-semibold text-lg hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
>>>>>>> Stashed changes
          >
            Finish Setup
          </button>
        </footer>
      </div>
    </div>
  );
};

export default GoalSettingScreen;