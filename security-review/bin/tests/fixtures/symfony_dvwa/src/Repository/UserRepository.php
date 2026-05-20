<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

class UserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function findActive(): array
    {
        return $this->createQueryBuilder('u')
            ->andWhere('u.roles LIKE :role')
            ->setParameter('role', '%ROLE_USER%')
            ->getQuery()
            ->getResult();
    }

    public function findByEmailUnsafe(string $email): array
    {
        // VULN: dql_concat id=DVWA-01
        // String-concatenated DQL — `$email` lands directly in the WHERE clause.
        // Sink_kind=dql_concat, root_cause_family=injection. Worker should
        // flag the concatenation, not the call site (which is many controllers away).
        return $this->getEntityManager()
            ->createQuery("SELECT u FROM App\\Entity\\User u WHERE u.email = '" . $email . "'")
            ->getResult();
    }
}
