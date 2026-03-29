import sinon from 'sinon';

export const stubPermissions = (owner, setCluster = false) => {
  const permissions = owner.lookup('service:permissions');
  const hasNavPermission = sinon.stub(permissions, 'hasNavPermission');
  hasNavPermission.returns(true);
  sinon.stub(permissions, 'navPathParams');

  const auth = owner.lookup('service:auth');
  sinon.stub(auth, 'authData').value({});

  if (setCluster) {
    owner.lookup('service:currentCluster').setCluster({
      id: 'foo',
      usingRaft: true,
    });
  }

  return { hasNavPermission };
};
