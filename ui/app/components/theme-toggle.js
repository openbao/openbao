import Component from '@glimmer/component';
import { service } from '@ember/service';

const ICONS = { system: 'circle-half', light: 'sun', dark: 'moon' };
const LABELS = { system: 'system mode', light: 'light mode', dark: 'dark mode' };

export default class ThemeToggle extends Component {
  @service theme;

  get mode() {
    return this.theme.choice ?? 'system';
  }

  get icon() {
    return ICONS[this.mode];
  }

  get label() {
    return LABELS[this.mode];
  }
}
