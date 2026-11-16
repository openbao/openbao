import Route from '@ember/routing/route';
import { inject as service } from '@ember/service';
import { withConfirmLeave } from 'core/decorators/confirm-leave';

@withConfirmLeave()
export default class PkiTidyAutoConfigureRoute extends Route {
  @service store;
  @service secretMountPath;

  // inherits model from tidy/auto

  setupController(controller, resolvedModel) {
    super.setupController(controller, resolvedModel);
    controller.breadcrumbs = [
      { label: 'secrets', route: 'secrets', linkExternal: true },
      {
        label: this.secretMountPath.currentPath,
        route: 'overview',
        models: [this.secretMountPath.currentPath],
      },
      { label: 'configuration', route: 'configuration.index', models: [this.secretMountPath.currentPath] },
      { label: 'tidy', route: 'tidy', models: [this.secretMountPath.currentPath] },
      { label: 'auto', route: 'tidy.auto', models: [this.secretMountPath.currentPath] },
      { label: 'configure' },
    ];
  }
}
