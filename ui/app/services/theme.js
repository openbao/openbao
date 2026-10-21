import Service from '@ember/service';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';

const STORAGE_KEY = 'theme';

export default class ThemeService extends Service {
  // Read saved value
  @tracked choice = localStorage.getItem(STORAGE_KEY);

  mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

  // Paint saved theme and call repaint whenever theme changes in OS
  constructor() {
    super(...arguments);
    this.mediaQuery.addEventListener('change', this.handleSystemChange);
    this.apply();
  }

  willDestroy() {
    super.willDestroy(...arguments);
    this.mediaQuery.removeEventListener('change', this.handleSystemChange);
  }

  @action
  handleSystemChange() {
    this.apply();
  }

  @action
  cycle() {
    // Update choice
    if (this.choice === null) {
      this.choice = 'light';
    } else if (this.choice === 'light') {
      this.choice = 'dark';
    } else {
      this.choice = null;
    }

    if (this.choice) {
      localStorage.setItem(STORAGE_KEY, this.choice);
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }

    this.apply();
  }

  // Check OS preference and set data-theme data attribute
  apply() {
    const systemMode = this.mediaQuery.matches ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', this.choice ?? systemMode); // use OS preference if user has not made a choice yet
  }
}
