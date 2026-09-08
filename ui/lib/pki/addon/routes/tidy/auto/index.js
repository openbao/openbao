import Route from '@ember/routing/route';
import { service } from '@ember/service';

export default class TidyAutoIndexRoute extends Route {
  @service secretMountPath;
  @service store;

  // inherits model from tidy/auto

  setupController(controller) {
    super.setupController(...arguments);
    controller.breadcrumbs = [
      { label: 'secrets', route: 'secrets', linkExternal: true },
      {
        label: this.secretMountPath.currentPath,
        route: 'overview',
        models: [this.secretMountPath.currentPath],
      },
      { label: 'tidy', route: 'tidy.index', models: [this.secretMountPath.currentPath] },
      { label: 'auto' },
    ];
    controller.title = this.secretMountPath.currentPath;
  }
}
