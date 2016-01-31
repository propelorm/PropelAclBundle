PropelAclBundle
===============

The `PropelAclBundle`_ is an extension to the `PropelBundle`_ enabling support for the Symfony Security ACL component.

Installation
------------

Before using this bundle in your project, add it to your ``composer.json`` file:

.. code-block:: bash

    $ composer require propel/propel-acl-bundle

Then, like for any other bundle, include it in your Kernel class::

    public function registerBundles()
    {
        $bundles = array(
            // ...

            new Propel\Bundle\PropelBundle\PropelBundle(),
            new Propel\Bundle\PropelAclBundle\PropelAclBundle(),
        );

        // ...
    }

.. tip::

    The ``PropelBundle`` needs to be enabled as well. If you don't have this bundle, the ``PropelAclBundle`` will be of no use.

Configuration
-------------

The bundle registers a service named ``propel.security.acl.provider`` which is an object of ``Propel\Bundle\PropelAclBundle\Security\Acl\AuditableAclProvider``.

The auditing of this provider is set to a sensible default. It will audit all ACL failures but no success by default.
If you also want to audit successful authorizations, you need to update the auditing of the given ACL accordingly.

To make use of this implementation you need to configure it in your `security.yml`_:

.. code-block:: yaml

    security:
        acl:
            provider: propel.security.acl.provider

.. tip::

    If you do not want to use the auditing in any way, you may override the service definition to use the ``Propel\Bundle\PropelAclBundle\Security\Acl\MutableAclProvider`` instead.

    .. configuration-block::

        .. code-block:: yaml

            services:
                propel.security.acl.provider:
                    public: false
                    class: Propel\Bundle\PropelAclBundle\Security\Acl\MutableAclProvider
                    arguments:
                        - '@security.acl.permission_granting_strategy'
                        - '@?propel.security.acl.connection'
                        - '@?security.acl.cache'

        .. code-block:: xml

            <?xml version="1.0" encoding="UTF-8" ?>
            <container xmlns="http://symfony.com/schema/dic/services"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xsi:schemaLocation="http://symfony.com/schema/dic/services http://symfony.com/schema/dic/services/services-1.0.xsd">

                <services>
                    <service id="propel.security.acl.provider" class="Propel\Bundle\PropelAclBundle\Security\Acl\AuditableAclProvider" public="false">
                        <argument type="service" id="security.acl.permission_granting_strategy" />
                        <argument type="service" id="propel.security.acl.connection" on-invalid="null" />
                        <argument type="service" id="security.acl.cache" on-invalid="null" />
                    </service>
                </services>
            </services>


Separate database connection for ACL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In case you want to use a different database connection for your ACL, you only need to configure the ``propel.security.acl.connection`` service.

.. configuration-block::

    .. code-block:: yaml

        services:
            propel.security.acl.connection:
                public: false
                class: PropelPDO
                factory: ['Propel', 'getConnection']
                arguments:
                    - "acl"

    .. code-block:: xml

        <?xml version="1.0" encoding="UTF-8" ?>
        <container xmlns="http://symfony.com/schema/dic/services"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xsi:schemaLocation="http://symfony.com/schema/dic/services http://symfony.com/schema/dic/services/services-1.0.xsd">

            <services>
                <service id="propel.security.acl.connection" class="PropelPDO" public="false">
                    <factory class="Propel" method="getConnection" />
                    <argument>acl</argument>
                </service>
            </services>
        </services>

The ``PropelAclBundle`` looks for this service, and if given uses the provided connection for all ACL related operations.
The given argument (``acl`` in the example) is the name of the connection to use, as defined in your runtime configuration.

.. _`PropelBundle`: https://github.com/propelorm/PropelBundle
.. _`PropelAclBundle`: https://github.com/propelorm/PropelAclBundle
.. _`security.yml`: http://symfony.com/doc/current/reference/configuration/security.html
