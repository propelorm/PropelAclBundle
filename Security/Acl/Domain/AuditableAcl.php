<?php

/**
 * This file is part of the PropelAclBundle package.
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @license    MIT License
 */
namespace Propel\Bundle\PropelAclBundle\Security\Acl\Domain;

use Propel\Bundle\PropelAclBundle\Model\Acl\Entry as ModelEntry;
use Symfony\Component\Security\Acl\Model\AuditableAclInterface;

/**
 * @author Toni Uebernickel <tuebernickel@gmail.com>
 */
class AuditableAcl extends MutableAcl implements AuditableAclInterface
{
    /**
     * {@inheritdoc}
     */
    public function updateClassAuditing($index, $auditSuccess, $auditFailure)
    {
        $this->updateAuditing($this->classAces, $index, $auditSuccess, $auditFailure);
    }

    /**
     * {@inheritdoc}
     */
    public function updateClassFieldAuditing($index, $field, $auditSuccess, $auditFailure)
    {
        $this->validateField($this->classFieldAces, $field);
        $this->updateAuditing($this->classFieldAces[$field], $index, $auditSuccess, $auditFailure);
    }

    /**
     * {@inheritdoc}
     */
    public function updateObjectAuditing($index, $auditSuccess, $auditFailure)
    {
        $this->updateAuditing($this->objectAces, $index, $auditSuccess, $auditFailure);
    }

    /**
     * {@inheritdoc}
     */
    public function updateObjectFieldAuditing($index, $field, $auditSuccess, $auditFailure)
    {
        $this->validateField($this->objectFieldAces, $field);
        $this->updateAuditing($this->objectFieldAces[$field], $index, $auditSuccess, $auditFailure);
    }

    /**
     * Update auditing on a single ACE.
     *
     * @throws \InvalidArgumentException
     *
     * @param array $list
     * @param int   $index
     * @param bool  $auditSuccess
     * @param bool  $auditFailure
     *
     * @return AuditableAcl
     */
    protected function updateAuditing(array &$list, $index, $auditSuccess, $auditFailure)
    {
        if (!is_bool($auditSuccess) or !is_bool($auditFailure)) {
            throw new \InvalidArgumentException('The given auditing flags are invalid. Please provide boolean only.');
        }

        $this->validateIndex($list, $index);

        $entry = ModelEntry::fromAclEntry($list[$index])
            ->setAuditSuccess($auditSuccess)
            ->setAuditFailure($auditFailure)
        ;

        $list[$index] = ModelEntry::toAclEntry($entry, $this);

        return $this;
    }
}
