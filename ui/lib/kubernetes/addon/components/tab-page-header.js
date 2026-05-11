import Component from '@glimmer/component';

export default class TabPageHeaderComponent extends Component {
  get urls() {
    return {
      list: 'vault.cluster.secrets.backend.kubernetes.roles',
    };
  }
}
